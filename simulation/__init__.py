"""Route registration for the local PhishShield simulation."""

import hmac
import secrets
import uuid
from collections import defaultdict, deque
from functools import wraps
from pathlib import Path
from threading import Lock
from time import monotonic

from flask import (
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from simulation.analytics import AnalyticsService
from simulation.campaign_service import public_sample
from simulation.database import DEFAULT_CAMPAIGN_ID
from simulation.event_store import EventStoreError


RESEARCH_DOCUMENTS = {
    "social_engineering_research.md": "social_engineering_research.md",
    "case_studies.md": "case_studies.md",
    "detection_indicators.md": "detection_indicators.md",
    "dataset_documentation.md": "data/dataset_documentation.md",
}
RESEARCH_DIRECTORY = Path(__file__).resolve().parents[1] / "research"
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60
_LOGIN_FAILURES = defaultdict(deque)
_LOGIN_FAILURES_LOCK = Lock()


def instructor_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("instructor_authenticated") is not True:
            return redirect(url_for("instructor_login"))
        return view(*args, **kwargs)

    return wrapped


def _login_attempts_limited(client_key):
    now = monotonic()
    with _LOGIN_FAILURES_LOCK:
        failures = _LOGIN_FAILURES[client_key]
        while failures and now - failures[0] >= LOGIN_FAILURE_WINDOW_SECONDS:
            failures.popleft()
        return len(failures) >= LOGIN_FAILURE_LIMIT


def _record_login_failure(client_key):
    now = monotonic()
    with _LOGIN_FAILURES_LOCK:
        failures = _LOGIN_FAILURES[client_key]
        while failures and now - failures[0] >= LOGIN_FAILURE_WINDOW_SECONDS:
            failures.popleft()
        failures.append(now)


def _clear_login_failures(client_key):
    with _LOGIN_FAILURES_LOCK:
        _LOGIN_FAILURES.pop(client_key, None)


def register_routes(app):
    @app.route("/instructor/login", methods=["GET", "POST"])
    def instructor_login():
        if session.get("instructor_authenticated") is True:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            verify_csrf()
            client_key = request.remote_addr or "unknown"
            if _login_attempts_limited(client_key):
                return render_template(
                    "instructor_login.html",
                    login_configured=app.config["INSTRUCTOR_LOGIN_CONFIGURED"],
                ), 429
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            configured_username = app.config["INSTRUCTOR_USERNAME"] or ""
            configured_password_hash = app.config["INSTRUCTOR_PASSWORD_HASH"] or ""
            try:
                password_matches = bool(configured_password_hash) and check_password_hash(
                    configured_password_hash,
                    password[:1024],
                )
            except (TypeError, ValueError):
                password_matches = False
            username_matches = hmac.compare_digest(
                username.encode("utf-8"),
                configured_username.encode("utf-8"),
            )
            if (
                app.config["INSTRUCTOR_LOGIN_CONFIGURED"]
                and len(username) <= 256
                and len(password) <= 1024
                and username_matches
                and password_matches
            ):
                session["instructor_authenticated"] = True
                session["instructor_username"] = configured_username
                session.permanent = True
                session["csrf_token"] = secrets.token_urlsafe(32)
                _clear_login_failures(client_key)
                return redirect(url_for("dashboard"))
            _record_login_failure(client_key)
            flash("The instructor username or password was not accepted.")
        return render_template(
            "instructor_login.html",
            login_configured=app.config["INSTRUCTOR_LOGIN_CONFIGURED"],
        )

    @app.post("/instructor/logout")
    @instructor_required
    def instructor_logout():
        verify_csrf()
        session.pop("instructor_authenticated", None)
        session.pop("instructor_username", None)
        session.permanent = False
        session["csrf_token"] = secrets.token_urlsafe(32)
        flash("You have been signed out of the instructor workspace.")
        return redirect(url_for("index"))

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/campaigns")
    def campaigns():
        samples = app.extensions["campaigns"]
        store = app.extensions["event_store"]
        selected_campaign_id = _selected_campaign_id(app)
        campaign_records = _campaign_records(store)
        if selected_campaign_id not in {
            campaign["campaign_id"] for campaign in campaign_records
        }:
            selected_campaign_id = (
                campaign_records[0]["campaign_id"] if campaign_records else None
            )
        if (
            selected_campaign_id
            and callable(getattr(store, "list_assigned_email_ids", None))
        ):
            assigned_ids = set(store.list_assigned_email_ids(selected_campaign_id))
            samples = [
                sample for sample in samples
                if sample["email_id"] in assigned_ids
            ]
        return render_template(
            "campaigns.html",
            campaigns=[public_sample(sample) for sample in samples],
            campaign_records=campaign_records,
            selected_campaign_id=selected_campaign_id,
        )

    @app.route("/campaigns/manage", methods=["GET", "POST"])
    @instructor_required
    def manage_campaigns():
        store = _campaign_management_store()
        if request.method == "POST":
            verify_csrf()
            action = request.form.get("action", "")
            try:
                if action == "create":
                    campaign_name = request.form.get("campaign_name", "").strip()
                    description = request.form.get("description", "").strip()
                    selected_email_ids = request.form.getlist("email_ids")
                    allowed_email_ids = {
                        sample["email_id"] for sample in app.extensions["campaigns"]
                    }
                    if not campaign_name or len(campaign_name) > 100:
                        flash("Campaign name must contain 1 to 100 characters.")
                        return redirect(url_for("manage_campaigns"))
                    if len(description) > 500:
                        flash("Campaign description must be 500 characters or fewer.")
                        return redirect(url_for("manage_campaigns"))
                    if not selected_email_ids or any(
                        email_id not in allowed_email_ids
                        for email_id in selected_email_ids
                    ):
                        flash("Select at least one available training email.")
                        return redirect(url_for("manage_campaigns"))
                    status = request.form.get("status", "active")
                    if status not in {"draft", "active"}:
                        flash("Choose draft or active as the campaign status.")
                        return redirect(url_for("manage_campaigns"))
                    campaign_id = f"classroom-{uuid.uuid4().hex[:12]}"
                    store.create_campaign(
                        campaign_id,
                        campaign_name,
                        description,
                        selected_email_ids,
                    )
                    if status == "active":
                        store.update_campaign_status(campaign_id, "active")
                    session["campaign_id"] = campaign_id
                    flash(f"Campaign created with {len(set(selected_email_ids))} assigned emails.")
                elif action == "select":
                    campaign_id = request.form.get("campaign_id", "").strip()
                    campaign = store.get_campaign(campaign_id)
                    if campaign is None:
                        abort(404)
                    if campaign["status"] == "completed":
                        flash("Completed campaigns cannot be selected for new activity.")
                        return redirect(url_for("manage_campaigns"))
                    if campaign["status"] == "draft":
                        store.update_campaign_status(campaign_id, "active")
                    session["campaign_id"] = campaign_id
                    flash("Selected campaign updated for this browser session.")
                elif action == "update":
                    campaign_id = request.form.get("campaign_id", "").strip()
                    name = request.form.get("campaign_name", "").strip()
                    description = request.form.get("description", "").strip()
                    email_ids = request.form.getlist("email_ids")
                    if request.form.get("update_emails") == "yes":
                        allowed_email_ids = {
                            sample["email_id"]
                            for sample in app.extensions["campaigns"]
                        }
                        if not email_ids or any(
                            email_id not in allowed_email_ids
                            for email_id in email_ids
                        ):
                            flash("Select at least one available training email.")
                            return redirect(url_for("manage_campaigns"))
                    updated = store.update_campaign(campaign_id, name, description)
                    if updated is None:
                        abort(404)
                    if request.form.get("update_emails") == "yes":
                        store.assign_campaign_samples(campaign_id, email_ids)
                    flash("Campaign details updated.")
                elif action == "status":
                    campaign_id = request.form.get("campaign_id", "").strip()
                    status = request.form.get("status", "")
                    updated = store.update_campaign_status(campaign_id, status)
                    if updated is None:
                        abort(404)
                    if status == "completed" and session.get("campaign_id") == campaign_id:
                        session.pop("campaign_id", None)
                    flash(f"Campaign status changed to {updated['status']}.")
                else:
                    abort(400)
            except ValueError as error:
                flash(str(error))
            except EventStoreError:
                current_app.logger.exception("Campaign management operation failed.")
                flash("The campaign could not be saved. Check the local database and try again.")
            return redirect(url_for("manage_campaigns"))

        campaign_records = store.list_campaigns()
        for campaign in campaign_records:
            campaign["email_ids"] = store.list_assigned_email_ids(
                campaign["campaign_id"]
            )
        return render_template(
            "campaign_management.html",
            campaigns=campaign_records,
            samples=app.extensions["campaigns"],
            selected_campaign_id=_selected_campaign_id(app),
        )

    @app.post("/campaign/select")
    @instructor_required
    def select_campaign():
        verify_csrf()
        store = _campaign_management_store()
        campaign_id = request.form.get("campaign_id", "").strip()
        campaign = store.get_campaign(campaign_id)
        if campaign is None:
            abort(404)
        if campaign["status"] == "completed":
            flash("Completed campaigns cannot be selected for new activity.")
        elif campaign["status"] == "paused":
            flash("Paused campaigns cannot be selected for new activity.")
        else:
            if campaign["status"] == "draft":
                store.update_campaign_status(campaign_id, "active")
            session["campaign_id"] = campaign_id
            flash("Selected campaign updated for this browser session.")
        return redirect(url_for("campaigns"))

    @app.get("/research")
    @instructor_required
    def research():
        store = app.extensions["event_store"]
        query = request.args.get("q", "").strip()[:100]
        category = request.args.get("category", "")
        classification = request.args.get("classification", "")
        samples = app.extensions["campaigns"]
        filtered_samples = [
            sample for sample in samples
            if (
                not query
                or query.casefold() in " ".join(
                    (
                        sample["subject"],
                        sample["scenario"],
                        sample["sender_display_name"],
                        sample["email_body"],
                    )
                ).casefold()
            )
            and (not category or sample["scenario"] == category)
            and (not classification or sample["email_type"] == classification)
        ]
        return render_template(
            "research.html",
            samples=[public_sample(sample) for sample in filtered_samples],
            research_samples=filtered_samples,
            query=query,
            selected_category=category,
            selected_classification=classification,
            categories=sorted({sample["scenario"] for sample in samples}),
            campaign_records=_campaign_records(store),
            selected_campaign_id=_selected_campaign_id(app),
        )

    @app.get("/research/email/<email_id>")
    @instructor_required
    def research_email(email_id):
        return render_template(
            "research_email.html",
            sample=find_sample(app, email_id),
        )

    @app.get("/research/document/<document_name>")
    @instructor_required
    def research_document(document_name):
        relative_path = RESEARCH_DOCUMENTS.get(document_name)
        if relative_path is None:
            abort(404)
        return Response(
            (RESEARCH_DIRECTORY / relative_path).read_text(encoding="utf-8"),
            mimetype="text/markdown",
        )

    @app.get("/help")
    def help_page():
        return render_template("help.html")

    @app.route("/join/<campaign_id>", methods=["GET", "POST"])
    def join_campaign(campaign_id):
        store = _participant_workflow_store()
        campaign = store.get_campaign(campaign_id)
        if campaign is None:
            abort(404)
        if request.method == "POST":
            verify_csrf()
            if campaign["status"] != "active":
                flash("This campaign is not currently accepting participants.")
                return redirect(url_for("join_campaign", campaign_id=campaign_id))
            if (
                session.get("joined_campaign_id") == campaign_id
                and session.get("participant_id")
            ):
                return redirect(url_for("participant_exercise", campaign_id=campaign_id))
            participant_id = f"participant-{uuid.uuid4().hex[:16]}"
            try:
                store.record_participant_action(
                    campaign_id,
                    participant_id,
                    "joined",
                )
            except ValueError as error:
                flash(str(error))
                return redirect(url_for("join_campaign", campaign_id=campaign_id))
            session["participant_id"] = participant_id
            session["joined_campaign_id"] = campaign_id
            session["campaign_id"] = campaign_id
            return redirect(url_for("participant_exercise", campaign_id=campaign_id))
        return render_template("participant_join.html", campaign=campaign)

    @app.get("/exercise/<campaign_id>")
    def participant_exercise(campaign_id):
        store = _participant_workflow_store()
        participant_id = _joined_participant(campaign_id)
        campaign = store.get_campaign(campaign_id)
        if campaign is None or campaign["status"] in {"paused", "completed"}:
            abort(404)
        progress = store.get_participant_progress(campaign_id, participant_id)
        next_email_id = next(
            (
                email_id for email_id in progress["assigned_email_ids"]
                if email_id not in progress["answers"]
            ),
            None,
        )
        if next_email_id is None:
            return render_template(
                "participant_exercise.html",
                campaign=campaign,
                sample=None,
                progress=progress,
                participant_id=participant_id,
            )
        return render_template(
            "participant_exercise.html",
            campaign=campaign,
            sample=public_sample(find_sample(app, next_email_id)),
            progress=progress,
            participant_id=participant_id,
        )

    @app.post("/exercise/<campaign_id>/next")
    def participant_next(campaign_id):
        verify_csrf()
        store = _participant_workflow_store()
        participant_id = _joined_participant(campaign_id)
        progress = store.get_participant_progress(campaign_id, participant_id)
        if any(
            email_id not in progress["answers"]
            for email_id in progress["assigned_email_ids"]
        ):
            return redirect(url_for("participant_exercise", campaign_id=campaign_id))
        store.record_participant_action(campaign_id, participant_id, "completed")
        return redirect(url_for("participant_complete", campaign_id=campaign_id))

    @app.post("/exercise/<campaign_id>/<email_id>/display")
    def participant_display(campaign_id, email_id):
        verify_csrf()
        store = _participant_workflow_store()
        participant_id = _joined_participant(campaign_id)
        _require_active_campaign(store, campaign_id)
        _participant_sample(store, app, campaign_id, email_id)
        progress = store.get_participant_progress(campaign_id, participant_id)
        if email_id in progress["answers"]:
            return redirect(
                url_for(
                    "participant_feedback",
                    campaign_id=campaign_id,
                    email_id=email_id,
                )
            )
        next_email_id = next(
            (
                assigned_id
                for assigned_id in progress["assigned_email_ids"]
                if assigned_id not in progress["answers"]
            ),
            None,
        )
        if email_id != next_email_id:
            abort(400)
        store.record_once(campaign_id, email_id, participant_id, "open")
        return redirect(
            url_for(
                "participant_email",
                campaign_id=campaign_id,
                email_id=email_id,
            )
        )

    @app.get("/exercise/<campaign_id>/<email_id>")
    def participant_email(campaign_id, email_id):
        store = _participant_workflow_store()
        participant_id = _joined_participant(campaign_id)
        sample = _participant_sample(store, app, campaign_id, email_id)
        displayed = any(
            event["participant_id"] == participant_id
            and event["event_type"] == "open"
            for event in store.list_events(
                campaign_id=campaign_id,
                email_id=email_id,
                limit=10000,
            )
        )
        if not displayed:
            return redirect(url_for("participant_exercise", campaign_id=campaign_id))
        feedback = store.participant_feedback(campaign_id, participant_id, email_id)
        if feedback is not None:
            return redirect(
                url_for(
                    "participant_feedback",
                    campaign_id=campaign_id,
                    email_id=email_id,
                )
            )
        return render_template(
            "participant_email.html",
            campaign=store.get_campaign(campaign_id),
            sample=public_sample(sample),
        )

    @app.post("/exercise/<campaign_id>/<email_id>/respond")
    def participant_respond(campaign_id, email_id):
        verify_csrf()
        store = _participant_workflow_store()
        participant_id = _joined_participant(campaign_id)
        sample = _participant_sample(store, app, campaign_id, email_id)
        existing = store.participant_feedback(campaign_id, participant_id, email_id)
        if existing is None:
            _require_active_campaign(store, campaign_id)
            displayed = any(
                event["participant_id"] == participant_id
                and event["event_type"] == "open"
                for event in store.list_events(
                    campaign_id=campaign_id,
                    email_id=email_id,
                    limit=10000,
                )
            )
            if not displayed:
                abort(400)
            response = request.form.get("response", "")
            if response not in {"phishing", "legitimate", "clicked"}:
                abort(400)
            is_correct = (
                None if response == "clicked"
                else response == sample["email_type"]
            )
            try:
                store.record_participant_action(
                    campaign_id,
                    participant_id,
                    "answered",
                    email_id=email_id,
                    response=response,
                    is_correct=is_correct,
                    simulation_event=(
                        "report" if response == "phishing"
                        else "click" if response == "clicked"
                        else None
                    ),
                )
            except ValueError as error:
                flash(str(error))
                return redirect(url_for("join_campaign", campaign_id=campaign_id))
        return redirect(
            url_for(
                "participant_feedback",
                campaign_id=campaign_id,
                email_id=email_id,
            )
        )

    @app.get("/exercise/<campaign_id>/<email_id>/feedback")
    def participant_feedback(campaign_id, email_id):
        store = _participant_workflow_store()
        participant_id = _joined_participant(campaign_id)
        sample = _participant_sample(store, app, campaign_id, email_id)
        action = store.participant_feedback(campaign_id, participant_id, email_id)
        if action is None:
            abort(404)
        return render_template(
            "participant_feedback.html",
            campaign=store.get_campaign(campaign_id),
            sample=sample,
            action=action,
        )

    @app.get("/exercise/<campaign_id>/complete")
    def participant_complete(campaign_id):
        store = _participant_workflow_store()
        participant_id = _joined_participant(campaign_id)
        progress = store.get_participant_progress(campaign_id, participant_id)
        if not any(
            action["action_type"] == "completed"
            for action in store.list_participant_actions(campaign_id, participant_id)
        ):
            abort(404)
        return render_template(
            "participant_complete.html",
            campaign=store.get_campaign(campaign_id),
            progress=progress,
        )

    @app.get("/campaign/<email_id>")
    def email_preview(email_id):
        sample = find_sample(app, email_id)
        return render_template(
            "email_preview.html",
            sample=public_sample(sample),
        )

    @app.post("/campaign/<email_id>/display")
    def start_simulation(email_id):
        verify_csrf()
        find_sample(app, email_id)
        _record_display(app, email_id, get_participant_id())
        return redirect(url_for("email_preview", email_id=email_id))

    @app.post("/campaign/<email_id>/click")
    def simulated_click(email_id):
        verify_csrf()
        sample = find_sample(app, email_id)
        participant_id = get_participant_id()
        _record_display(app, email_id, participant_id)
        event, _created = app.extensions["event_store"].record_once(
            campaign_id=_selected_campaign_id(app),
            email_id=email_id,
            participant_id=participant_id,
            event_type="click",
        )
        return redirect(url_for("feedback", event_id=event["event_id"]))

    @app.post("/campaign/<email_id>/report")
    def report_email(email_id):
        verify_csrf()
        find_sample(app, email_id)
        participant_id = get_participant_id()
        _record_display(app, email_id, participant_id)
        event, _created = app.extensions["event_store"].record_once(
            campaign_id=_selected_campaign_id(app),
            email_id=email_id,
            participant_id=participant_id,
            event_type="report",
        )
        return redirect(url_for("feedback", event_id=event["event_id"]))

    @app.get("/feedback/<event_id>")
    def feedback(event_id):
        event = app.extensions["event_store"].get_event(event_id)
        if event is None:
            abort(404)
        if event["participant_id"] != session.get("participant_id"):
            abort(404)
        sample = find_sample(app, event["email_id"])
        return render_template(
            "feedback.html",
            sample=sample,
            event=event,
        )

    @app.get("/instructor")
    @instructor_required
    def instructor_summary():
        store = app.extensions["event_store"]
        campaign_id = _selected_campaign_id(app)
        return render_template(
            "instructor_summary.html",
            campaigns=app.extensions["campaigns"],
            summary=store.summary(campaign_id=campaign_id),
            events=store.list_events(campaign_id=campaign_id),
            campaign_records=(
                store.list_campaigns() if hasattr(store, "list_campaigns") else []
            ),
        )

    @app.get("/dashboard")
    @instructor_required
    def dashboard():
        analytics = _analytics_service()
        selected_campaign_id = request.args.get("campaign_id") or None
        data = analytics.dashboard_data(campaign_id=selected_campaign_id)
        if selected_campaign_id is not None and not data["campaigns"]:
            abort(404)
        return render_template(
            "dashboard.html",
            data=data,
            detail_mode=False,
        )

    @app.route("/detection", methods=["GET", "POST"])
    def detection_tool():
        samples = app.extensions["campaigns"]
        selected_email_id = ""
        result = None
        form_values = {
            "sender_display_name": "",
            "sender_email": "",
            "reply_to": "",
            "subject": "",
            "email_body": "",
            "urls": "",
        }
        if request.method == "POST":
            verify_csrf()
            selected_email_id = request.form.get("email_id", "").strip()
            if selected_email_id:
                sample = find_sample(app, selected_email_id)
            else:
                limits = {
                    "sender_display_name": 150,
                    "sender_email": 320,
                    "reply_to": 320,
                    "subject": 500,
                    "email_body": 20000,
                    "urls": 4096,
                }
                for field, maximum in limits.items():
                    form_values[field] = request.form.get(field, "").strip()
                    if len(form_values[field]) > maximum:
                        flash(f"{field.replace('_', ' ').title()} exceeds {maximum} characters.")
                        return render_template(
                            "detection.html",
                            samples=[public_sample(sample) for sample in samples],
                            selected_email_id="",
                            result=None,
                            form_values=form_values,
                        )
                if not form_values["subject"] and not form_values["email_body"]:
                    flash("Enter a subject or message body to analyze.")
                    return render_template(
                        "detection.html",
                        samples=[public_sample(sample) for sample in samples],
                        selected_email_id="",
                        result=None,
                        form_values=form_values,
                    )
                url_items = [
                    value.strip()
                    for value in form_values["urls"].replace(",", "\n").splitlines()
                    if value.strip()
                ]
                if len(url_items) > 20:
                    flash("Provide no more than 20 URL entries.")
                    return render_template(
                        "detection.html",
                        samples=[public_sample(sample) for sample in samples],
                        selected_email_id="",
                        result=None,
                        form_values=form_values,
                    )
                sample = {
                    key: form_values[key]
                    for key in (
                        "sender_display_name",
                        "sender_email",
                        "reply_to",
                        "subject",
                        "email_body",
                    )
                }
                sample["urls"] = [
                    {"text": url, "url": url} for url in url_items
                ]
            from detection import PhishingDetector

            result = PhishingDetector().analyze(sample)
        return render_template(
            "detection.html",
            samples=[public_sample(sample) for sample in samples],
            selected_email_id=selected_email_id,
            result=result,
            form_values=form_values,
        )

    @app.get("/dashboard/campaign/<campaign_id>")
    @instructor_required
    def campaign_dashboard(campaign_id):
        data = _analytics_service().campaign_detail(campaign_id)
        if data is None:
            abort(404)
        return render_template(
            "dashboard.html",
            data=data,
            detail_mode=True,
        )

    @app.get("/dashboard/export.csv")
    @instructor_required
    def export_dashboard_csv():
        csv_content = _analytics_service().export_campaign_csv()
        return Response(
            csv_content,
            mimetype="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="phishshield-campaign-summary.csv"'
            },
        )


def _analytics_service():
    database_path = current_app.extensions.get("database_path")
    if database_path is None:
        abort(503, description="Dashboard analytics require the SQLite event store.")
    return AnalyticsService(database_path)


def _campaign_management_store():
    store = current_app.extensions["event_store"]
    if not _supports_campaign_management(store):
        abort(503, description="Campaign management requires the persistent SQLite event store.")
    return store


def _supports_campaign_management(store):
    required_methods = (
        "list_campaigns",
        "get_campaign",
        "create_campaign",
        "update_campaign_status",
        "update_campaign",
        "assign_campaign_samples",
        "list_assigned_email_ids",
    )
    return all(callable(getattr(store, method, None)) for method in required_methods)


def _participant_workflow_store():
    store = current_app.extensions["event_store"]
    required_methods = (
        "record_participant_action",
        "get_participant_progress",
        "participant_feedback",
        "list_participant_actions",
        "list_assigned_email_ids",
    )
    if not all(callable(getattr(store, method, None)) for method in required_methods):
        abort(503, description="Participant exercises require the persistent SQLite event store.")
    return store


def _joined_participant(campaign_id):
    participant_id = session.get("participant_id")
    if (
        not participant_id
        or session.get("joined_campaign_id") != campaign_id
    ):
        abort(404)
    return participant_id


def _require_active_campaign(store, campaign_id):
    campaign = store.get_campaign(campaign_id)
    if campaign is None:
        abort(404)
    if campaign["status"] != "active":
        abort(400, description="This campaign is not accepting participant activity.")


def _participant_sample(store, app, campaign_id, email_id):
    if email_id not in store.list_assigned_email_ids(campaign_id):
        abort(404)
    return find_sample(app, email_id)


def _campaign_records(store):
    if not _supports_campaign_management(store):
        return []
    campaigns = _selectable_campaigns(store.list_campaigns())
    for campaign in campaigns:
        campaign["email_count"] = len(
            store.list_assigned_email_ids(campaign["campaign_id"])
        )
    return campaigns


def _selected_campaign_id(app):
    store = app.extensions["event_store"]
    campaign_id = session.get("campaign_id", app.extensions["campaign_id"])
    if hasattr(store, "get_campaign") and store.get_campaign(campaign_id) is None:
        campaign_id = DEFAULT_CAMPAIGN_ID
    return campaign_id


def _selectable_campaigns(campaigns):
    return [
        campaign for campaign in campaigns
        if campaign["status"] == "active"
    ]


def _record_display(app, email_id, participant_id):
    store = app.extensions["event_store"]
    campaign_id = _selected_campaign_id(app)
    if callable(getattr(store, "get_campaign", None)):
        campaign = store.get_campaign(campaign_id)
        if campaign is None:
            abort(404)
        if campaign["status"] != "active":
            abort(400, description="This campaign is not accepting participant activity.")
    if callable(getattr(store, "list_assigned_email_ids", None)):
        if email_id not in store.list_assigned_email_ids(campaign_id):
            abort(404)
    store.record_once(
        campaign_id=campaign_id,
        email_id=email_id,
        participant_id=participant_id,
        event_type="open",
    )


def find_sample(app, email_id):
    for sample in app.extensions["campaigns"]:
        if sample["email_id"] == email_id:
            return sample
    abort(404)


def get_participant_id():
    participant_id = session.get("participant_id")
    if participant_id is None:
        participant_id = f"participant-{uuid.uuid4().hex[:12]}"
        session["participant_id"] = participant_id
    return participant_id


def verify_csrf():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not submitted or not hmac.compare_digest(expected, submitted):
        abort(400)
