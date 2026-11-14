import os
import re
import secrets
from unittest.mock import patch

from werkzeug.security import generate_password_hash


TEST_INSTRUCTOR_USERNAME = "test-" + secrets.token_hex(8)
TEST_INSTRUCTOR_PASSWORD = secrets.token_urlsafe(32)
TEST_SECRET_KEY = secrets.token_hex(32)
TEST_INSTRUCTOR_PASSWORD_HASH = generate_password_hash(
    TEST_INSTRUCTOR_PASSWORD,
    method="pbkdf2:sha256",
)


def instructor_environment():
    return patch.dict(
        os.environ,
        {
            "PHISHSHIELD_ENV": "testing",
            "PHISHSHIELD_SECRET_KEY": TEST_SECRET_KEY,
            "PHISHSHIELD_INSTRUCTOR_USERNAME": TEST_INSTRUCTOR_USERNAME,
            "PHISHSHIELD_INSTRUCTOR_PASSWORD_HASH": TEST_INSTRUCTOR_PASSWORD_HASH,
        },
    )


def configure_test_instructor(test_case):
    environment = instructor_environment()
    environment.start()
    test_case.addCleanup(environment.stop)


def login_instructor(client):
    login_page = client.get("/instructor/login")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', login_page.data)
    if token is None:
        raise AssertionError("The instructor login page did not render a CSRF token.")
    return client.post(
        "/instructor/login",
        data={
            "csrf_token": token.group(1).decode("ascii"),
            "username": TEST_INSTRUCTOR_USERNAME,
            "password": TEST_INSTRUCTOR_PASSWORD,
        },
    )