import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from auth_test_support import configure_test_instructor, login_instructor
from simulation.campaign_service import DEFAULT_DATASET_PATH
from simulation.database import DEFAULT_CAMPAIGN_ID
from simulation.event_store import InMemoryEventStore
from simulation.campaign_service import load_campaigns


class IntegratedApplicationTests(unittest.TestCase):
    def setUp(self):
        configure_test_instructor(self)
        self.store = InMemoryEventStore()
        self.app = create_app(
            dataset_path=DEFAULT_DATASET_PATH,
            event_store=self.store,
            secret_key="integration-test-key",
        )
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()
        self.assertEqual(login_instructor(self.client).status_code, 302)

    def csrf_token(self):
        response = self.client.get("/detection")
        match = re.search(
            rb'name="csrf_token" value="([^"]+)"',
            response.data,
        )
        self.assertIsNotNone(match)
        return match.group(1).decode("ascii")

    def test_primary_navigation_pages_and_research_documents_load(self):
        for route in ("/", "/research", "/campaigns", "/instructor", "/help"):
            with self.subTest(route=route):
                response = self.client.get(route)
                self.assertEqual(response.status_code, 200)
                for label in (b"Research", b"Simulation", b"Tracking", b"Dashboard", b"Detection", b"Help"):
                    self.assertIn(label, response.data)

        research = self.client.get("/research")
        self.assertIn(b"Training Email Library", research.data)
        self.assertIn(
            b"fictional educational examples, not real or intercepted emails",
            research.data,
        )
        self.assertNotIn(b"label-phishing", research.data)
        report = self.client.get(
            "/research/document/social_engineering_research.md"
        )
        favicon = self.client.get("/static/favicon.svg")
        self.assertEqual(report.status_code, 200)
        self.assertTrue(report.mimetype.startswith("text/markdown"))
        self.assertIn(b"Social engineering", report.data)
        self.assertEqual(favicon.status_code, 200)
        self.assertTrue(favicon.mimetype.startswith("image/svg+xml"))
        favicon.close()
        favicon_alias = self.client.get("/favicon.ico", follow_redirects=True)
        self.assertEqual(favicon_alias.status_code, 200)
        self.assertTrue(favicon_alias.mimetype.startswith("image/svg+xml"))
        favicon_alias.close()
        self.assertEqual(
            self.client.get("/research/document/unknown.md").status_code,
            404,
        )

    def test_sample_analysis_is_explainable_and_does_not_record_campaign_event(self):
        response = self.client.post(
            "/detection",
            data={
                "csrf_token": self.csrf_token(),
                "email_id": "PS-PH-001",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Heuristic risk score", response.data)
        self.assertIn(b"Rule-by-rule results", response.data)
        self.assertIn(b"Limitations", response.data)
        self.assertEqual(self.store.summary()["total_events"], 0)

    def test_detection_requires_csrf_and_valid_sample(self):
        missing_token = self.client.post(
            "/detection",
            data={"email_id": "PS-PH-001"},
        )
        invalid_sample = self.client.post(
            "/detection",
            data={
                "csrf_token": self.csrf_token(),
                "email_id": "not-a-sample",
            },
        )

        self.assertEqual(missing_token.status_code, 400)
        self.assertEqual(invalid_sample.status_code, 404)
        self.assertEqual(self.store.summary()["total_events"], 0)

    def test_simulation_event_and_detector_result_remain_independent(self):
        token = self.csrf_token()
        self.client.post(
            "/campaign/PS-PH-001/click",
            data={"csrf_token": token},
        )
        click_count = self.store.summary()["clicks"]

        analyzed = self.client.post(
            "/detection",
            data={"csrf_token": token, "email_id": "PS-PH-001"},
        )

        self.assertEqual(analyzed.status_code, 200)
        self.assertEqual(self.store.summary()["clicks"], click_count)
        self.assertEqual(self.store.summary()["opened"], 1)
        self.assertEqual(self.store.summary()["total_events"], 2)

    def test_app_import_does_not_create_a_global_database_backed_app(self):
        self.assertNotIn("app", getattr(sys.modules["app"], "__dict__", {}))

    def test_database_path_environment_override_is_used(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "isolated.sqlite"
            with patch.dict(
                "os.environ",
                {"PHISHSHIELD_DATABASE_PATH": str(database_path)},
            ):
                isolated_app = create_app(
                    dataset_path=DEFAULT_DATASET_PATH,
                    secret_key="isolated-database-test",
                )

            self.assertTrue(database_path.is_file())
            self.assertEqual(
                isolated_app.extensions["database_path"],
                database_path,
            )

    def test_campaign_create_and_selection_use_session_and_store(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "campaigns.sqlite"
            isolated_app = create_app(
                dataset_path=DEFAULT_DATASET_PATH,
                database_path=database_path,
                secret_key="campaign-management-test",
            )
            isolated_app.config.update(TESTING=True)
            client = isolated_app.test_client()
            self.assertEqual(login_instructor(client).status_code, 302)
            token_response = client.get("/campaigns")
            token = re.search(
                rb'name="csrf_token" value="([^"]+)"',
                token_response.data,
            ).group(1).decode("ascii")

            created = client.post(
                "/campaigns/manage",
                data={
                    "csrf_token": token,
                    "action": "create",
                    "campaign_name": "MCA classroom exercise",
                    "description": "Temporary integration test campaign",
                    "status": "active",
                    "email_ids": ["PS-PH-001"],
                },
            )

            self.assertEqual(created.status_code, 302)
            with client.session_transaction() as browser_session:
                created_campaign_id = browser_session["campaign_id"]

            store = isolated_app.extensions["event_store"]
            created_campaign = store.get_campaign(created_campaign_id)
            self.assertEqual(created_campaign["campaign_name"], "MCA classroom exercise")
            self.assertEqual(created_campaign["status"], "active")

            display = client.post(
                "/campaign/PS-PH-001/display",
                data={"csrf_token": token},
            )
            self.assertEqual(display.status_code, 302)
            self.assertEqual(
                store.summary(campaign_id=created_campaign_id)["opened"],
                1,
            )

            client.post(
                "/campaign/select",
                data={
                    "csrf_token": token,
                    "campaign_id": DEFAULT_CAMPAIGN_ID,
                },
            )
            with client.session_transaction() as browser_session:
                self.assertEqual(browser_session["campaign_id"], DEFAULT_CAMPAIGN_ID)

            preview = client.get("/campaign/PS-PH-001")
            self.assertEqual(preview.status_code, 200)
            self.assertEqual(
                store.summary(campaign_id=DEFAULT_CAMPAIGN_ID)["total_events"],
                0,
            )


class ParticipantWorkflowTests(unittest.TestCase):
    def setUp(self):
        configure_test_instructor(self)
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "phishshield.sqlite"
        self.app = create_app(
            dataset_path=DEFAULT_DATASET_PATH,
            database_path=self.database_path,
            secret_key="participant-workflow-test",
        )
        self.app.config.update(TESTING=True)
        self.admin = self.app.test_client()
        self.assertEqual(login_instructor(self.admin).status_code, 302)
        self.participant = self.app.test_client()
        self.samples = {
            sample["email_id"]: sample for sample in load_campaigns()
        }

    def tearDown(self):
        self.temporary_directory.cleanup()

    @staticmethod
    def csrf_token(response):
        token = re.search(
            rb'name="csrf_token" value="([^"]+)"',
            response.data,
        )
        if token is None:
            raise AssertionError("The page did not render a CSRF token.")
        return token.group(1).decode("ascii")

    def test_campaign_join_decisions_feedback_and_completion_are_persisted(self):
        token = self.csrf_token(self.admin.get("/campaigns/manage"))
        created = self.admin.post(
            "/campaigns/manage",
            data={
                "csrf_token": token,
                "action": "create",
                "campaign_name": "Email safety exercise",
                "description": "Two messages for the integration test.",
                "status": "draft",
                "email_ids": ["PS-PH-001", "PS-LEG-001"],
            },
        )
        self.assertEqual(created.status_code, 302)
        with self.admin.session_transaction() as browser_session:
            campaign_id = browser_session["campaign_id"]

        store = self.app.extensions["event_store"]
        self.assertEqual(store.get_campaign(campaign_id)["status"], "draft")
        self.assertEqual(
            set(store.list_assigned_email_ids(campaign_id)),
            {"PS-PH-001", "PS-LEG-001"},
        )

        status = self.admin.post(
            "/campaigns/manage",
            data={
                "csrf_token": token,
                "action": "status",
                "campaign_id": campaign_id,
                "status": "active",
            },
        )
        self.assertEqual(status.status_code, 302)
        join_page = self.participant.get(f"/join/{campaign_id}")
        self.assertEqual(join_page.status_code, 200)
        participant_token = self.csrf_token(join_page)
        self.assertEqual(
            store.list_participant_actions(campaign_id, "not-joined"),
            [],
        )
        joined = self.participant.post(
            f"/join/{campaign_id}",
            data={"csrf_token": participant_token},
        )
        self.assertEqual(joined.status_code, 302)
        with self.participant.session_transaction() as browser_session:
            participant_id = browser_session["participant_id"]
        self.assertEqual(
            store.get_participant_progress(campaign_id, participant_id)["answers"],
            {},
        )
        self.assertEqual(store.summary(campaign_id)["opened"], 0)

        for email_id in store.list_assigned_email_ids(campaign_id):
            exercise = self.participant.get(f"/exercise/{campaign_id}")
            self.assertEqual(exercise.status_code, 200)
            self.assertIn(b"Present message", exercise.data)
            display = self.participant.post(
                f"/exercise/{campaign_id}/{email_id}/display",
                data={"csrf_token": participant_token},
            )
            self.assertEqual(display.status_code, 302)
            message = self.participant.get(
                f"/exercise/{campaign_id}/{email_id}"
            )
            self.assertEqual(message.status_code, 200)
            self.assertNotIn(b"email_type", message.data)

            response = "phishing"
            submitted = self.participant.post(
                f"/exercise/{campaign_id}/{email_id}/respond",
                data={"csrf_token": participant_token, "response": response},
            )
            self.assertEqual(submitted.status_code, 302)
            duplicate = self.participant.post(
                f"/exercise/{campaign_id}/{email_id}/respond",
                data={"csrf_token": participant_token, "response": response},
            )
            self.assertEqual(duplicate.status_code, 302)
            feedback = self.participant.get(
                f"/exercise/{campaign_id}/{email_id}/feedback"
            )
            self.assertEqual(feedback.status_code, 200)
            self.assertIn(self.samples[email_id]["email_type"].encode(), feedback.data)
            self.participant.post(
                f"/exercise/{campaign_id}/next",
                data={"csrf_token": participant_token},
            )

        complete = self.participant.get(
            f"/exercise/{campaign_id}/complete"
        )
        self.assertEqual(complete.status_code, 200)
        self.assertIn(b"EXERCISE COMPLETE", complete.data)
        summary = store.summary(campaign_id)
        self.assertEqual(summary["opened"], 2)
        self.assertEqual(summary["reports"], 2)
        self.assertEqual(summary["unique_participants"], 1)

        from simulation.analytics import AnalyticsService

        dashboard = AnalyticsService(self.database_path).dashboard_data(campaign_id)
        self.assertEqual(dashboard["summary"]["correct_responses"], 1)
        self.assertEqual(dashboard["summary"]["incorrect_responses"], 1)
        self.assertEqual(dashboard["summary"]["completion_rate"], 100)
        self.assertEqual(len(dashboard["recent_activity"]), 8)
        self.assertEqual(
            self.admin.get(f"/dashboard/campaign/{campaign_id}").status_code,
            200,
        )

    def test_campaign_can_be_paused_and_resumed_without_losing_assignments(self):
        token = self.csrf_token(self.admin.get("/campaigns/manage"))
        self.admin.post(
            "/campaigns/manage",
            data={
                "csrf_token": token,
                "action": "create",
                "campaign_name": "Pause test",
                "status": "active",
                "email_ids": ["PS-PH-001"],
            },
        )
        with self.admin.session_transaction() as browser_session:
            campaign_id = browser_session["campaign_id"]
        self.admin.post(
            "/campaigns/manage",
            data={
                "csrf_token": token,
                "action": "status",
                "campaign_id": campaign_id,
                "status": "paused",
            },
        )
        store = self.app.extensions["event_store"]
        self.assertEqual(store.get_campaign(campaign_id)["status"], "paused")
        self.assertEqual(store.list_assigned_email_ids(campaign_id), ["PS-PH-001"])

        join_page = self.participant.get(f"/join/{campaign_id}")
        self.assertIn(b"not accepting participants", join_page.data)
        join_token = self.csrf_token(self.participant.get("/detection"))
        response = self.participant.post(
            f"/join/{campaign_id}",
            data={"csrf_token": join_token},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            store.list_campaign_participants(campaign_id),
            [],
        )

        self.admin.post(
            "/campaigns/manage",
            data={
                "csrf_token": token,
                "action": "status",
                "campaign_id": campaign_id,
                "status": "active",
            },
        )
        self.assertEqual(store.get_campaign(campaign_id)["status"], "active")

    def test_manual_detection_uses_python_rules_and_does_not_log_simulation_events(self):
        token = self.csrf_token(self.admin.get("/detection"))
        response = self.admin.post(
            "/detection",
            data={
                "csrf_token": token,
                "sender_display_name": "Campus Account Support",
                "sender_email": "notice@example.test",
                "reply_to": "reply@other.test",
                "subject": "Urgent account suspension today",
                "email_body": "Review your account now.",
                "urls": "https://192.0.2.10/verify",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Heuristic risk score", response.data)
        self.assertIn(b"Reply To Mismatch", response.data)
        self.assertIn(b"Url Risk", response.data)
        self.assertEqual(
            self.app.extensions["event_store"].summary()["total_events"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
