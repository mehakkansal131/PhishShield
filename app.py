"""Local-only entry point for the PhishShield educational simulation."""

import hashlib
import os
import re
import secrets
from datetime import timedelta
from pathlib import Path

from flask import Flask, redirect, render_template, session, url_for

from simulation.campaign_service import CampaignDataError, load_campaigns
from simulation.database import DEFAULT_CAMPAIGN_ID
from simulation.event_store import SQLiteEventStore


SUPPORTED_ENVIRONMENTS = {"development", "testing", "production"}


def _is_valid_werkzeug_password_hash(password_hash):
    if not isinstance(password_hash, str):
        return False

    try:
        method, salt, digest = password_hash.split("$")
    except ValueError:
        return False

    if (
        not re.fullmatch(r"[A-Za-z0-9]+", salt)
        or not re.fullmatch(r"[0-9a-f]+", digest)
    ):
        return False

    method_parts = method.split(":")
    if method_parts[0] == "scrypt":
        if len(method_parts) == 1:
            cost, block_size, parallelism = 2**15, 8, 1
        elif len(method_parts) == 4 and all(
            re.fullmatch(r"[1-9][0-9]*", value)
            for value in method_parts[1:]
        ):
            cost, block_size, parallelism = map(int, method_parts[1:])
        else:
            return False
        if (
            cost < 2
            or cost & (cost - 1)
            or block_size * parallelism == 0
            or cost * block_size * parallelism > 1_048_576
        ):
            return False
        digest_size = 64
    elif method_parts[0] == "pbkdf2":
        if len(method_parts) not in {1, 2, 3}:
            return False
        hash_name = method_parts[1] if len(method_parts) >= 2 else "sha256"
        if len(method_parts) == 3:
            if not re.fullmatch(r"[1-9][0-9]*", method_parts[2]):
                return False
            if int(method_parts[2]) > 10_000_000:
                return False
        try:
            digest_size = hashlib.new(hash_name).digest_size
            hashlib.pbkdf2_hmac(hash_name, b"", b"", 1)
        except (TypeError, ValueError):
            return False
    else:
        return False

    return len(digest) == digest_size * 2


def create_app(
    dataset_path=None,
    event_store=None,
    secret_key=None,
    database_path=None,
):
    app = Flask(__name__)
    configured_environment = os.environ.get("PHISHSHIELD_ENV")
    environment = (
        "development"
        if configured_environment is None
        else configured_environment.strip().lower()
    )
    if environment not in SUPPORTED_ENVIRONMENTS:
        supported_values = ", ".join(sorted(SUPPORTED_ENVIRONMENTS))
        raise RuntimeError(
            f"Unsupported PHISHSHIELD_ENV value. Supported values are: {supported_values}."
        )
    is_production = environment == "production"
    configured_secret_key = os.environ.get("PHISHSHIELD_SECRET_KEY")
    instructor_username = os.environ.get("PHISHSHIELD_INSTRUCTOR_USERNAME")
    instructor_password_hash = os.environ.get("PHISHSHIELD_INSTRUCTOR_PASSWORD_HASH")

    if is_production:
        missing_configuration = [
            name
            for name, value in (
                ("PHISHSHIELD_SECRET_KEY", configured_secret_key),
                ("PHISHSHIELD_INSTRUCTOR_USERNAME", instructor_username),
                ("PHISHSHIELD_INSTRUCTOR_PASSWORD_HASH", instructor_password_hash),
            )
            if not value
        ]
        if missing_configuration:
            raise RuntimeError(
                "Missing required production configuration: "
                + ", ".join(missing_configuration)
            )
        if len(configured_secret_key) < 32:
            raise RuntimeError("PHISHSHIELD_SECRET_KEY must contain at least 32 characters.")
        if not _is_valid_werkzeug_password_hash(instructor_password_hash):
            raise RuntimeError(
                "PHISHSHIELD_INSTRUCTOR_PASSWORD_HASH must be a complete, valid Werkzeug scrypt or PBKDF2 hash."
            )

    app_secret_key = (
        configured_secret_key
        if is_production
        else secret_key or configured_secret_key or secrets.token_hex(32)
    )
    app.config.update(
        SECRET_KEY=app_secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=is_production,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_REFRESH_EACH_REQUEST=True,
        PHISHSHIELD_ENV=environment,
        INSTRUCTOR_USERNAME=instructor_username,
        INSTRUCTOR_PASSWORD_HASH=instructor_password_hash,
        INSTRUCTOR_LOGIN_CONFIGURED=bool(instructor_username and instructor_password_hash),
        DEBUG=False,
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    dataset_error = None
    try:
        campaigns = load_campaigns(dataset_path)
    except CampaignDataError as error:
        campaigns = []
        dataset_error = str(error)
        app.logger.error(
            "The sample dataset is unavailable; starting with training pages disabled: %s",
            error,
        )

    if event_store is None:
        configured_database_path = os.environ.get("PHISHSHIELD_DATABASE_PATH")
        db_path = Path(
            database_path
            or configured_database_path
            or Path(app.instance_path) / "phishshield.db"
        )
        event_store = SQLiteEventStore(db_path, campaigns)
        app.extensions["database_path"] = db_path

    app.extensions["event_store"] = event_store
    app.extensions["campaigns"] = campaigns
    app.extensions["dataset_error"] = dataset_error
    app.extensions["campaign_id"] = DEFAULT_CAMPAIGN_ID

    @app.context_processor
    def provide_csrf_token():
        token = session.get("csrf_token")
        if token is None:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return {
            "csrf_token": token,
            "dataset_error": app.extensions.get("dataset_error"),
            "instructor_authenticated": session.get("instructor_authenticated") is True,
            "environment_label": "PRODUCTION" if is_production else "LOCAL TRAINING ONLY",
        }

    @app.after_request
    def mark_training_environment(response):
        response.headers["X-PhishShield-Environment"] = (
            "production" if is_production else "local-training"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/favicon.ico")
    def favicon():
        return redirect(url_for("static", filename="favicon.svg"))

    @app.errorhandler(400)
    def bad_request(_error):
        return render_template("error.html", message="That training action could not be accepted."), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", message="That training page or scenario was not found."), 404

    from simulation import register_routes

    register_routes(app)
    return app


def main():
    app = create_app()
    port = int(os.environ.get("PHISHSHIELD_PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
