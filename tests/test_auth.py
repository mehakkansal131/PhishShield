import re
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

from app import create_app
from simulation.campaign_service import DEFAULT_DATASET_PATH
from simulation.database import DEFAULT_CAMPAIGN_ID
from simulation.event_store import InMemoryEventStore
from auth_test_support import (
    TEST_INSTRUCTOR_PASSWORD,
    TEST_INSTRUCTOR_PASSWORD_HASH,
    TEST_INSTRUCTOR_USERNAME,
    TEST_SECRET_KEY,
    instructor_environment,
    login_instructor,
)


class AuthenticationAndAccessTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "phishshield.sqlite"
        self.environment = instructor_environment()
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.app = create_app(
            dataset_path=DEFAULT_DATASET_PATH,
            database_path=self.database_path,
        )
        self.app.config.update(TESTING=True)
        self.anonymous = self.app.test_client()

    def tearDown(self):
        self.temporary_directory.cleanup()

    @staticmethod
    def csrf_token(response):
        token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        if token is None:
            raise AssertionError("The page did not render a CSRF token.")
        return token.group(1).decode("ascii")

    def test_instructor_login_rejects_bad_password_and_accepts_valid_hash(self):
        login_page = self.anonymous.get("/instructor/login")
        csrf = self.csrf_token(login_page)
        rejected = self.anonymous.post(
            "/instructor/login",
            data={
                "csrf_token": csrf,
                "username": TEST_INSTRUCTOR_USERNAME,
                "password": "incorrect-password",
            },
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertIn(b"username or password was not accepted", rejected.data)
        self.assertEqual(self.anonymous.get("/dashboard").status_code, 302)

        accepted = login_instructor(self.anonymous)
        self.assertEqual(accepted.status_code, 302)
        self.assertEqual(accepted.headers["Location"], "/dashboard")
        self.assertEqual(self.anonymous.get("/dashboard").status_code, 200)
        with self.anonymous.session_transaction() as browser_session:
            self.assertTrue(browser_session.permanent)
            self.assertTrue(browser_session["instructor_authenticated"])

    def test_instructor_login_throttles_repeated_failures(self):
        client = self.app.test_client()
        client.environ_base["REMOTE_ADDR"] = "203.0.113.25"
        csrf = self.csrf_token(client.get("/instructor/login"))
        for _attempt in range(5):
            response = client.post(
                "/instructor/login",
                data={
                    "csrf_token": csrf,
                    "username": TEST_INSTRUCTOR_USERNAME,
                    "password": "incorrect-password",
                },
            )
            self.assertEqual(response.status_code, 200)
        limited = client.post(
            "/instructor/login",
            data={
                "csrf_token": csrf,
                "username": TEST_INSTRUCTOR_USERNAME,
                "password": "incorrect-password",
            },
        )
        self.assertEqual(limited.status_code, 429)

    def test_all_instructor_urls_require_server_side_login(self):
        protected_gets = (
            "/campaigns/manage",
            "/research",
            "/research/email/PS-PH-001",
            "/research/document/social_engineering_research.md",
            "/instructor",
            "/dashboard",
            f"/dashboard/campaign/{DEFAULT_CAMPAIGN_ID}",
            "/dashboard/export.csv",
        )
        for route in protected_gets:
            with self.subTest(route=route):
                response = self.anonymous.get(route)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["Location"], "/instructor/login")

        post_response = self.anonymous.post(
            "/campaigns/manage",
            data={"action": "create", "campaign_name": "Unauthorized"},
        )
        select_response = self.anonymous.post(
            "/campaign/select",
            data={"campaign_id": DEFAULT_CAMPAIGN_ID},
        )
        self.assertEqual(post_response.status_code, 302)
        self.assertEqual(select_response.status_code, 302)

    def test_logout_requires_csrf_and_session_expiry_removes_access(self):
        client = self.app.test_client()
        login_instructor(client)
        dashboard = client.get("/dashboard")
        token = self.csrf_token(dashboard)

        self.assertEqual(client.post("/instructor/logout").status_code, 400)
        logged_out = client.post(
            "/instructor/logout",
            data={"csrf_token": token},
        )
        self.assertEqual(logged_out.status_code, 302)
        self.assertEqual(client.get("/dashboard").status_code, 302)

        expired_client = self.app.test_client()
        self.app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=-1)
        serializer = self.app.session_interface.get_signing_serializer(self.app)
        expired_cookie = serializer.dumps(
            {
                "_permanent": True,
                "instructor_authenticated": True,
                "instructor_username": TEST_INSTRUCTOR_USERNAME,
            }
        )
        expired_client.set_cookie(self.app.config["SESSION_COOKIE_NAME"], expired_cookie)
        self.assertEqual(expired_client.get("/dashboard").status_code, 302)

    def test_participant_can_join_assigned_exercise_without_instructor_access(self):
        participant = self.app.test_client()
        join_page = participant.get(f"/join/{DEFAULT_CAMPAIGN_ID}")
        self.assertEqual(join_page.status_code, 200)
        joined = participant.post(
            f"/join/{DEFAULT_CAMPAIGN_ID}",
            data={"csrf_token": self.csrf_token(join_page)},
        )
        self.assertEqual(joined.status_code, 302)
        exercise = participant.get(f"/exercise/{DEFAULT_CAMPAIGN_ID}")
        self.assertEqual(exercise.status_code, 200)
        self.assertEqual(participant.get("/dashboard").status_code, 302)
        self.assertEqual(participant.get("/campaigns/manage").status_code, 302)

    def test_participant_cannot_access_another_participants_feedback(self):
        first = self.app.test_client()
        second = self.app.test_client()
        for participant in (first, second):
            join_page = participant.get(f"/join/{DEFAULT_CAMPAIGN_ID}")
            participant.post(
                f"/join/{DEFAULT_CAMPAIGN_ID}",
                data={"csrf_token": self.csrf_token(join_page)},
            )

        message = first.get("/campaign/PS-PH-001")
        token = self.csrf_token(message)
        click = first.post(
            "/campaign/PS-PH-001/click",
            data={"csrf_token": token},
        )
        event_feedback_url = click.headers["Location"]
        self.assertEqual(first.get(event_feedback_url).status_code, 200)
        self.assertEqual(second.get(event_feedback_url).status_code, 404)

        second_id = second.get(f"/exercise/{DEFAULT_CAMPAIGN_ID}")
        self.assertEqual(second_id.status_code, 200)
        self.assertEqual(
            second.get(f"/exercise/{DEFAULT_CAMPAIGN_ID}/PS-PH-001/feedback").status_code,
            404,
        )

    def test_production_requires_all_secrets_and_uses_secure_cookie(self):
        missing_configuration_database = (
            Path(self.temporary_directory.name) / "must-not-be-created.sqlite"
        )
        with patch.dict(
            "os.environ",
            {"PHISHSHIELD_ENV": "production", "PHISHSHIELD_SECRET_KEY": ""},
        ):
            with self.assertRaisesRegex(RuntimeError, "PHISHSHIELD_SECRET_KEY"):
                create_app(
                    dataset_path=DEFAULT_DATASET_PATH,
                    database_path=missing_configuration_database,
                )
        self.assertFalse(missing_configuration_database.exists())

        with patch.dict(
            "os.environ",
            {
                "PHISHSHIELD_ENV": "production",
                "PHISHSHIELD_SECRET_KEY": TEST_SECRET_KEY,
                "PHISHSHIELD_INSTRUCTOR_USERNAME": TEST_INSTRUCTOR_USERNAME,
                "PHISHSHIELD_INSTRUCTOR_PASSWORD_HASH": TEST_INSTRUCTOR_PASSWORD_HASH,
            },
        ):
            production_app = create_app(
                dataset_path=DEFAULT_DATASET_PATH,
                database_path=self.database_path,
                secret_key=TEST_SECRET_KEY[::-1],
            )
        self.assertTrue(production_app.config["SESSION_COOKIE_SECURE"])
        self.assertFalse(production_app.config["DEBUG"])
        self.assertEqual(
            production_app.secret_key,
            TEST_SECRET_KEY,
        )
        self.assertEqual(
            production_app.config["INSTRUCTOR_PASSWORD_HASH"],
            TEST_INSTRUCTOR_PASSWORD_HASH,
        )

    def test_environment_defaults_to_development_and_rejects_unknown_values(self):
        invalid_database = Path(self.temporary_directory.name) / "invalid-env.sqlite"
        for value in ("staging", "prod", ""):
            with self.subTest(value=value):
                with patch.dict("os.environ", {"PHISHSHIELD_ENV": value}):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "Unsupported PHISHSHIELD_ENV",
                    ):
                        create_app(
                            dataset_path=DEFAULT_DATASET_PATH,
                            database_path=invalid_database,
                        )
        self.assertFalse(invalid_database.exists())

        for value in ("development", "testing"):
            with self.subTest(value=value):
                with patch.dict("os.environ", {"PHISHSHIELD_ENV": value}):
                    app = create_app(
                        dataset_path=DEFAULT_DATASET_PATH,
                        event_store=InMemoryEventStore(),
                        secret_key=TEST_SECRET_KEY,
                    )
                self.assertEqual(app.config["PHISHSHIELD_ENV"], value)

        with patch.dict("os.environ", {}, clear=True):
            local_app = create_app(
                dataset_path=DEFAULT_DATASET_PATH,
                event_store=InMemoryEventStore(),
                secret_key=TEST_SECRET_KEY,
            )
        self.assertEqual(local_app.config["PHISHSHIELD_ENV"], "development")
        self.assertFalse(local_app.config["SESSION_COOKIE_SECURE"])

    def test_production_accepts_werkzeug_default_scrypt_hash(self):
        scrypt_hash = generate_password_hash(TEST_INSTRUCTOR_PASSWORD)
        with patch.dict(
            "os.environ",
            {
                "PHISHSHIELD_ENV": "production",
                "PHISHSHIELD_SECRET_KEY": TEST_SECRET_KEY,
                "PHISHSHIELD_INSTRUCTOR_USERNAME": TEST_INSTRUCTOR_USERNAME,
                "PHISHSHIELD_INSTRUCTOR_PASSWORD_HASH": scrypt_hash,
            },
        ):
            app = create_app(
                dataset_path=DEFAULT_DATASET_PATH,
                event_store=InMemoryEventStore(),
            )
        self.assertEqual(app.config["INSTRUCTOR_PASSWORD_HASH"], scrypt_hash)

    def test_production_rejects_malformed_incomplete_and_unsupported_hashes(self):
        malformed_hashes = (
            "not-a-hash",
            "scrypt:32768:8:1$abc123",
            "scrypt:32767:8:1$abc123$" + "0" * 128,
            "scrypt:32768:invalid:1$abc123$" + "0" * 128,
            "pbkdf2:sha256:many$abc123$" + "0" * 64,
            "pbkdf2:sha256:1000000$abc123$" + "0" * 62,
            "pbkdf2:sha256:1000000$abc123$" + "z" * 64,
            "argon2id$abc123$" + "0" * 64,
        )
        for password_hash in malformed_hashes:
            with self.subTest(password_hash=password_hash[:32]):
                with patch.dict(
                    "os.environ",
                    {
                        "PHISHSHIELD_ENV": "production",
                        "PHISHSHIELD_SECRET_KEY": TEST_SECRET_KEY,
                        "PHISHSHIELD_INSTRUCTOR_USERNAME": TEST_INSTRUCTOR_USERNAME,
                        "PHISHSHIELD_INSTRUCTOR_PASSWORD_HASH": password_hash,
                    },
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "complete, valid Werkzeug",
                    ):
                        create_app(
                            dataset_path=DEFAULT_DATASET_PATH,
                            event_store=InMemoryEventStore(),
                        )


if __name__ == "__main__":
    unittest.main()