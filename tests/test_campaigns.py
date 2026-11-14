import json
import re
import tempfile
import unittest
from pathlib import Path

from app import create_app
from auth_test_support import configure_test_instructor, login_instructor
from simulation.campaign_service import DEFAULT_DATASET_PATH
from simulation.event_store import InMemoryEventStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class CampaignRouteTests(unittest.TestCase):
    def setUp(self):
        configure_test_instructor(self)
        self.store = InMemoryEventStore()
        self.app = create_app(
            dataset_path=DEFAULT_DATASET_PATH,
            event_store=self.store,
            secret_key="test-key-for-local-unit-tests",
        )
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()
        self.assertEqual(login_instructor(self.client).status_code, 302)

    def csrf_token(self):
        response = self.client.get("/campaigns")
        self.assertEqual(response.status_code, 200)
        match = re.search(
            rb'name="csrf_token" value="([^"]+)"',
            self.client.get("/campaign/PS-PH-001").data,
        )
        self.assertIsNotNone(match)
        return match.group(1).decode("ascii")

    def test_home_and_campaign_pages_load(self):
        home = self.client.get("/")
        campaign_page = self.client.get("/campaigns")

        self.assertEqual(home.status_code, 200)
        self.assertIn(b"LOCAL TRAINING ONLY", home.data)
        self.assertEqual(campaign_page.status_code, 200)
        self.assertIn(b"Review the practice account notice", campaign_page.data)
        self.assertIn(b"PS-LEG-005", campaign_page.data)
        self.assertNotIn(b"phishing", campaign_page.data.lower())

    def test_valid_sample_displays_content_without_external_link(self):
        response = self.client.get("/campaign/PS-PH-001")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PhishShield Account Desk", response.data)
        self.assertIn(b"Review the practice account notice", response.data)
        self.assertIn(b"example.com/training/account-review", response.data)
        self.assertNotIn(b'href="https://example.com', response.data)
        self.assertNotIn(b'type="password"', response.data.lower())
        self.assertNotIn(b"email_type", response.data)
        self.assertEqual(self.store.summary()["opened"], 0)

    def test_dataset_html_is_rendered_as_text(self):
        samples = json.loads(DEFAULT_DATASET_PATH.read_text(encoding="utf-8"))
        samples[0]["email_body"] = "Practice text <script>alert('unsafe')</script>"

        with tempfile.TemporaryDirectory() as temporary_directory:
            dataset_path = Path(temporary_directory) / "samples.json"
            dataset_path.write_text(json.dumps(samples), encoding="utf-8")
            isolated_app = create_app(
                dataset_path=dataset_path,
                event_store=InMemoryEventStore(),
                secret_key="test-key-for-local-unit-tests",
            )
            response = isolated_app.test_client().get("/campaign/PS-PH-001")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertNotIn(b"<script>alert('unsafe')</script>", response.data)

    def test_preview_get_and_refresh_do_not_record_display(self):
        self.client.get("/campaign/PS-PH-002")
        self.client.get("/campaign/PS-PH-002")
        prefetch = self.client.head("/campaign/PS-PH-002")

        self.assertEqual(prefetch.status_code, 200)
        self.assertEqual(self.store.summary()["opened"], 0)

    def test_explicit_display_post_records_once_and_redirects_to_preview(self):
        token = self.csrf_token()
        first = self.client.post(
            "/campaign/PS-PH-002/display",
            data={"csrf_token": token},
        )
        second = self.client.post(
            "/campaign/PS-PH-002/display",
            data={"csrf_token": token},
        )

        self.assertEqual(first.status_code, 302)
        self.assertEqual(first.headers["Location"], "/campaign/PS-PH-002")
        self.assertEqual(second.status_code, 302)
        self.assertEqual(self.store.summary()["opened"], 1)

    def test_unknown_scenario_returns_404(self):
        response = self.client.get("/campaign/not-a-real-id")

        self.assertEqual(response.status_code, 404)

    def test_click_is_local_and_recorded_once(self):
        token = self.csrf_token()
        first = self.client.post(
            "/campaign/PS-PH-001/click",
            data={"csrf_token": token},
        )
        second = self.client.post(
            "/campaign/PS-PH-001/click",
            data={"csrf_token": token},
        )

        self.assertEqual(first.status_code, 302)
        self.assertEqual(second.status_code, 302)
        self.assertTrue(first.headers["Location"].startswith("/feedback/"))
        self.assertEqual(self.store.summary()["clicks"], 1)
        self.assertEqual(self.store.summary()["opened"], 1)
        feedback = self.client.get(first.headers["Location"])
        self.assertEqual(feedback.status_code, 200)
        self.assertIn(b"simulated phishing action", feedback.data)
        self.assertIn(
            b"no credentials or personal information were collected",
            feedback.data.lower(),
        )

    def test_report_records_event_and_displays_confirmation(self):
        token = self.csrf_token()
        response = self.client.post(
            "/campaign/PS-PH-003/report",
            data={"csrf_token": token},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.store.summary()["reports"], 1)
        self.assertEqual(self.store.summary()["opened"], 1)
        feedback = self.client.get(response.headers["Location"])
        self.assertEqual(feedback.status_code, 200)
        self.assertIn(b"Thank you for reporting", feedback.data)

    def test_state_changing_request_requires_valid_csrf_token(self):
        display_missing_token = self.client.post(
            "/campaign/PS-PH-001/display",
        )
        missing_token = self.client.post("/campaign/PS-PH-001/click")
        invalid_token = self.client.post(
            "/campaign/PS-PH-001/report",
            data={"csrf_token": "not-the-session-token"},
        )

        self.assertEqual(display_missing_token.status_code, 400)
        self.assertEqual(missing_token.status_code, 400)
        self.assertEqual(invalid_token.status_code, 400)
        self.assertEqual(self.store.summary()["opened"], 0)
        self.assertEqual(self.store.summary()["clicks"], 0)
        self.assertEqual(self.store.summary()["reports"], 0)

    def test_instructor_summary_shows_totals_and_labels(self):
        token = self.csrf_token()
        self.client.post(
            "/campaign/PS-PH-001/click",
            data={"csrf_token": token},
        )
        response = self.client.get("/instructor")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Instructor activity summary", response.data)
        self.assertIn(b"phishing", response.data)
        self.assertIn(b"Simulated clicks", response.data)


class DatasetErrorTests(unittest.TestCase):
    def test_missing_dataset_starts_in_degraded_mode_with_visible_warning(self):
        missing_path = PROJECT_ROOT / "does-not-exist-sample-data.json"
        with tempfile.TemporaryDirectory() as temporary_directory:
            app = create_app(
                dataset_path=missing_path,
                event_store=InMemoryEventStore(),
                secret_key="test-key",
                database_path=Path(temporary_directory) / "phishshield.db",
            )
            app.config.update(TESTING=True)
            client = app.test_client()

            home = client.get("/")
            scenarios = client.get("/campaigns")

        self.assertEqual(home.status_code, 200)
        self.assertIn(b"Sample dataset unavailable", home.data)
        self.assertEqual(scenarios.status_code, 200)
        self.assertIn(b"No training scenarios are available", scenarios.data)

    def test_malformed_dataset_starts_in_degraded_mode_with_visible_warning(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            malformed_path = Path(temporary_directory) / "malformed.json"
            malformed_path.write_text("{ invalid json", encoding="utf-8")

            app = create_app(
                dataset_path=malformed_path,
                event_store=InMemoryEventStore(),
                secret_key="test-key",
                database_path=Path(temporary_directory) / "phishshield.db",
            )
            app.config.update(TESTING=True)
            response = app.test_client().get("/help")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Sample dataset unavailable", response.data)

    def test_empty_or_incomplete_dataset_starts_without_sample_actions(self):
        for contents in ("[]", '[{"email_id":"incomplete"}]'):
            with self.subTest(contents=contents):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    dataset_path = Path(temporary_directory) / "samples.json"
                    dataset_path.write_text(contents, encoding="utf-8")
                    app = create_app(
                        dataset_path=dataset_path,
                        event_store=InMemoryEventStore(),
                        secret_key="test-key",
                        database_path=Path(temporary_directory) / "phishshield.db",
                    )
                    app.config.update(TESTING=True)
                    client = app.test_client()

                    self.assertEqual(client.get("/").status_code, 200)
                    self.assertEqual(client.get("/research").status_code, 302)
                    self.assertEqual(client.get("/detection").status_code, 200)


if __name__ == "__main__":
    unittest.main()
