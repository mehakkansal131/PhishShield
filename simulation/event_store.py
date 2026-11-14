"""Event-store adapters used by the Flask simulation."""

import hashlib
import sqlite3
from datetime import datetime, timezone
from threading import RLock
from uuid import uuid4

from simulation.database import (
    DEFAULT_CAMPAIGN_ID,
    database_connection,
    initialize_database,
    utc_timestamp,
)


DATABASE_EVENT_TYPES = {
    "open": "displayed",
    "click": "clicked",
    "report": "reported",
}
APPLICATION_EVENT_TYPES = {
    database_type: application_type
    for application_type, database_type in DATABASE_EVENT_TYPES.items()
}


class EventStoreError(RuntimeError):
    """Raised when a persistent event-store operation fails."""


class SQLiteEventStore:
    """Persistent SQLite implementation of Module 2's event-store interface."""

    def __init__(
        self,
        database_path,
        email_samples,
        campaign_id=DEFAULT_CAMPAIGN_ID,
    ):
        self.database_path = database_path
        self.campaign_id = campaign_id
        initialize_database(database_path, email_samples, campaign_id)

    def record_once(self, campaign_id, email_id, participant_id, event_type):
        stored_type = DATABASE_EVENT_TYPES.get(event_type)
        if stored_type is None:
            raise ValueError(f"Unsupported event type: {event_type}")
        if not all(
            isinstance(value, str) and value.strip()
            for value in (campaign_id, email_id, participant_id)
        ):
            raise ValueError("Campaign, email, and participant IDs must be non-empty.")

        idempotency_key = _make_idempotency_key(
            campaign_id, email_id, participant_id, stored_type
        )
        timestamp = utc_timestamp()
        try:
            with database_connection(self.database_path) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT OR IGNORE INTO participants (
                        participant_id, display_name, created_at
                    ) VALUES (?, NULL, ?)
                    """,
                    (participant_id, timestamp),
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO events (
                        event_id, campaign_id, email_id, participant_id,
                        event_type, timestamp, session_event_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        uuid4().hex,
                        campaign_id,
                        email_id,
                        participant_id,
                        stored_type,
                        timestamp,
                        idempotency_key,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT event_id, campaign_id, email_id, participant_id,
                           event_type, timestamp
                    FROM events
                    WHERE session_event_key = ?
                    """,
                    (idempotency_key,),
                ).fetchone()
                if row is None:
                    raise EventStoreError(
                        "The event could not be recorded or retrieved."
                    )
                created = connection.execute(
                    "SELECT changes()"
                ).fetchone()[0] == 1
                connection.commit()
                return _application_event(row), created
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not record simulation event: {error}") from error

    def get_event(self, event_id):
        try:
            with database_connection(self.database_path) as connection:
                row = connection.execute(
                    """
                    SELECT event_id, campaign_id, email_id, participant_id,
                           event_type, timestamp
                    FROM events
                    WHERE event_id = ?
                    """,
                    (event_id,),
                ).fetchone()
                return _application_event(row) if row is not None else None
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not retrieve simulation event: {error}") from error

    def list_events(self, limit=1000, campaign_id=None, email_id=None):
        if not isinstance(limit, int) or not 1 <= limit <= 10000:
            raise ValueError("Event list limit must be between 1 and 10000.")

        conditions = []
        parameters = []
        if campaign_id is not None:
            conditions.append("campaign_id = ?")
            parameters.append(campaign_id)
        if email_id is not None:
            conditions.append("email_id = ?")
            parameters.append(email_id)
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        parameters.append(limit)

        try:
            with database_connection(self.database_path) as connection:
                rows = connection.execute(
                    f"""
                    SELECT event_id, campaign_id, email_id, participant_id,
                           event_type, timestamp
                    FROM events
                    {where_clause}
                    ORDER BY timestamp DESC, event_id DESC
                    LIMIT ?
                    """,
                    parameters,
                ).fetchall()
                return [_application_event(row) for row in rows]
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not list simulation events: {error}") from error

    def summary(self, campaign_id=None):
        condition = "WHERE campaign_id = ?" if campaign_id is not None else ""
        parameters = (campaign_id,) if campaign_id is not None else ()
        try:
            with database_connection(self.database_path) as connection:
                row = connection.execute(
                    f"""
                    SELECT
                        SUM(CASE WHEN event_type = 'displayed' THEN 1 ELSE 0 END) AS opened,
                        SUM(CASE WHEN event_type = 'clicked' THEN 1 ELSE 0 END) AS clicks,
                        SUM(CASE WHEN event_type = 'reported' THEN 1 ELSE 0 END) AS reports,
                        COUNT(DISTINCT participant_id) AS unique_participants,
                        COUNT(*) AS total_events
                    FROM events
                    {condition}
                    """,
                    parameters,
                ).fetchone()
                return {
                    "opened": row["opened"] or 0,
                    "clicks": row["clicks"] or 0,
                    "reports": row["reports"] or 0,
                    "unique_participants": row["unique_participants"] or 0,
                    "total_events": row["total_events"] or 0,
                }
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not calculate event summary: {error}") from error

    def campaign_statistics(self, campaign_id):
        campaign = self.get_campaign(campaign_id)
        if campaign is None:
            return None
        statistics = self.summary(campaign_id=campaign_id)
        return {"campaign": campaign, **statistics}

    def update_campaign(self, campaign_id, campaign_name, description=""):
        if not isinstance(campaign_name, str) or not campaign_name.strip():
            raise ValueError("Campaign name must be a non-empty string.")
        if len(campaign_name.strip()) > 100:
            raise ValueError("Campaign name must be 100 characters or fewer.")
        if not isinstance(description, str) or len(description) > 500:
            raise ValueError("Campaign description must be 500 characters or fewer.")
        try:
            with database_connection(self.database_path) as connection:
                cursor = connection.execute(
                    """
                    UPDATE campaigns
                    SET campaign_name = ?, description = ?
                    WHERE campaign_id = ? AND status != 'completed'
                    """,
                    (campaign_name.strip(), description.strip(), campaign_id),
                )
                if cursor.rowcount == 0:
                    return None
                connection.commit()
            return self.get_campaign(campaign_id)
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not update campaign details: {error}") from error

    def assign_campaign_samples(self, campaign_id, email_ids):
        if not isinstance(email_ids, (list, tuple)) or not email_ids:
            raise ValueError("Select at least one training email.")
        if any(not isinstance(email_id, str) or not email_id.strip() for email_id in email_ids):
            raise ValueError("Training email IDs must be non-empty strings.")
        selected_ids = list(dict.fromkeys(email_id.strip() for email_id in email_ids))
        now = utc_timestamp()
        try:
            with database_connection(self.database_path) as connection:
                connection.execute("BEGIN IMMEDIATE")
                campaign = connection.execute(
                    "SELECT status FROM campaigns WHERE campaign_id = ?",
                    (campaign_id,),
                ).fetchone()
                if campaign is None:
                    raise ValueError("Campaign does not exist.")
                if campaign["status"] != "draft":
                    raise ValueError("Email assignments can only be changed on draft campaigns.")
                if connection.execute(
                    "SELECT 1 FROM participant_actions WHERE campaign_id = ? LIMIT 1",
                    (campaign_id,),
                ).fetchone() or connection.execute(
                    "SELECT 1 FROM events WHERE campaign_id = ? LIMIT 1",
                    (campaign_id,),
                ).fetchone():
                    raise ValueError("A campaign with participant activity cannot be reassigned.")
                missing = [
                    email_id
                    for email_id in selected_ids
                    if connection.execute(
                        "SELECT 1 FROM email_samples WHERE email_id = ?",
                        (email_id,),
                    ).fetchone() is None
                ]
                if missing:
                    raise ValueError("One or more selected training emails do not exist.")
                connection.execute(
                    "DELETE FROM campaign_email_assignments WHERE campaign_id = ?",
                    (campaign_id,),
                )
                connection.executemany(
                    """
                    INSERT INTO campaign_email_assignments (
                        campaign_id, email_id, assigned_at
                    ) VALUES (?, ?, ?)
                    """,
                    [(campaign_id, email_id, now) for email_id in selected_ids],
                )
                connection.commit()
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not assign campaign emails: {error}") from error

    def list_assigned_email_ids(self, campaign_id):
        try:
            with database_connection(self.database_path) as connection:
                rows = connection.execute(
                    """
                    SELECT email_id FROM campaign_email_assignments
                    WHERE campaign_id = ?
                    ORDER BY assigned_at, email_id
                    """,
                    (campaign_id,),
                ).fetchall()
                return [row["email_id"] for row in rows]
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not list assigned emails: {error}") from error

    def record_participant_action(
        self,
        campaign_id,
        participant_id,
        action_type,
        email_id=None,
        response=None,
        is_correct=None,
        simulation_event=None,
    ):
        if not isinstance(action_type, str) or action_type not in {
            "joined",
            "answered",
            "completed",
        }:
            raise ValueError("Unsupported participant action.")
        if simulation_event is not None and (
            action_type != "answered"
            or simulation_event not in DATABASE_EVENT_TYPES
        ):
            raise ValueError("Unsupported simulation event for participant response.")
        if not all(
            isinstance(value, str) and value.strip()
            for value in (campaign_id, participant_id)
        ):
            raise ValueError("Campaign and participant IDs must be non-empty.")
        if action_type == "answered":
            if not isinstance(email_id, str) or not email_id.strip():
                raise ValueError("An answer must reference a training email.")
            if response not in {"phishing", "legitimate", "clicked"}:
                raise ValueError("Choose phishing, legitimate, or the simulated link.")
            if response == "clicked":
                if is_correct is not None:
                    raise ValueError("A simulated-link action has no classification score.")
            elif not isinstance(is_correct, bool):
                raise ValueError("A classification response requires a correctness value.")
        elif email_id is not None or response is not None or is_correct is not None:
            raise ValueError("Join and completion actions do not accept email responses.")

        normalized_email_id = email_id.strip() if isinstance(email_id, str) else ""
        key = _make_action_key(
            campaign_id, participant_id, action_type, normalized_email_id
        )
        timestamp = utc_timestamp()
        try:
            with database_connection(self.database_path) as connection:
                connection.execute("BEGIN IMMEDIATE")
                campaign = connection.execute(
                    """
                    SELECT c.status, p.campaign_id AS paused
                    FROM campaigns AS c
                    LEFT JOIN campaign_pauses AS p ON p.campaign_id = c.campaign_id
                    WHERE c.campaign_id = ?
                    """,
                    (campaign_id,),
                ).fetchone()
                if campaign is None:
                    raise ValueError("Campaign does not exist.")
                if action_type != "completed" and (
                    campaign["status"] != "active" or campaign["paused"] is not None
                ):
                    raise ValueError("This campaign is not accepting participant activity.")
                if action_type == "answered" and connection.execute(
                    """
                    SELECT 1 FROM campaign_email_assignments
                    WHERE campaign_id = ? AND email_id = ?
                    """,
                    (campaign_id, normalized_email_id),
                ).fetchone() is None:
                    raise ValueError("This email is not assigned to the campaign.")
                if action_type in {"answered", "completed"} and connection.execute(
                    """
                    SELECT 1 FROM participant_actions
                    WHERE campaign_id = ? AND participant_id = ?
                        AND action_type = 'joined'
                    """,
                    (campaign_id, participant_id),
                ).fetchone() is None:
                    raise ValueError("Join the campaign before submitting responses.")
                if action_type == "completed":
                    missing_answers = connection.execute(
                        """
                        SELECT COUNT(*) FROM campaign_email_assignments AS a
                        WHERE a.campaign_id = ?
                            AND NOT EXISTS (
                                SELECT 1 FROM participant_actions AS pa
                                WHERE pa.campaign_id = a.campaign_id
                                    AND pa.email_id = a.email_id
                                    AND pa.participant_id = ?
                                    AND pa.action_type = 'answered'
                            )
                        """,
                        (campaign_id, participant_id),
                    ).fetchone()[0]
                    if missing_answers:
                        raise ValueError("Answer every assigned message before completing.")

                connection.execute(
                    """
                    INSERT OR IGNORE INTO participants (
                        participant_id, display_name, created_at
                    ) VALUES (?, NULL, ?)
                    """,
                    (participant_id, timestamp),
                )
                if simulation_event is not None:
                    stored_type = DATABASE_EVENT_TYPES[simulation_event]
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO events (
                            event_id, campaign_id, email_id, participant_id,
                            event_type, timestamp, session_event_key
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            uuid4().hex,
                            campaign_id,
                            normalized_email_id,
                            participant_id,
                            stored_type,
                            timestamp,
                            _make_idempotency_key(
                                campaign_id,
                                normalized_email_id,
                                participant_id,
                                stored_type,
                            ),
                        ),
                    )
                insert_cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO participant_actions (
                        action_id, campaign_id, participant_id, email_id,
                        action_type, response, is_correct, timestamp, action_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        uuid4().hex,
                        campaign_id,
                        participant_id,
                        normalized_email_id or None,
                        action_type,
                        response,
                        None if is_correct is None else int(is_correct),
                        timestamp,
                        key,
                    ),
                )
                row = connection.execute(
                    """
                    SELECT action_id, campaign_id, participant_id, email_id,
                           action_type, response, is_correct, timestamp
                    FROM participant_actions
                    WHERE action_key = ?
                    """,
                    (key,),
                ).fetchone()
                if row is None and action_type == "answered":
                    row = connection.execute(
                        """
                        SELECT action_id, campaign_id, participant_id, email_id,
                               action_type, response, is_correct, timestamp
                        FROM participant_actions
                        WHERE campaign_id = ? AND participant_id = ?
                            AND email_id = ? AND action_type = 'answered'
                        """,
                        (campaign_id, participant_id, normalized_email_id),
                    ).fetchone()
                if row is None:
                    raise EventStoreError("The participant action could not be retrieved.")
                connection.commit()
                action = dict(row)
                if action["is_correct"] is not None:
                    action["is_correct"] = bool(action["is_correct"])
                return action, insert_cursor.rowcount == 1
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not record participant action: {error}") from error

    def get_participant_progress(self, campaign_id, participant_id):
        try:
            with database_connection(self.database_path) as connection:
                assigned = connection.execute(
                    """
                    SELECT a.email_id FROM campaign_email_assignments AS a
                    WHERE a.campaign_id = ? ORDER BY a.assigned_at, a.email_id
                    """,
                    (campaign_id,),
                ).fetchall()
                answers = connection.execute(
                    """
                    SELECT email_id, response, is_correct
                    FROM participant_actions
                    WHERE campaign_id = ? AND participant_id = ?
                        AND action_type = 'answered'
                    """,
                    (campaign_id, participant_id),
                ).fetchall()
                return {
                    "assigned_email_ids": [row["email_id"] for row in assigned],
                    "answers": {
                        row["email_id"]: {
                            "response": row["response"],
                            "is_correct": (
                                None if row["is_correct"] is None
                                else bool(row["is_correct"])
                            ),
                        }
                        for row in answers
                    },
                }
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not retrieve participant progress: {error}") from error

    def participant_feedback(self, campaign_id, participant_id, email_id):
        try:
            with database_connection(self.database_path) as connection:
                row = connection.execute(
                    """
                    SELECT action_id, campaign_id, participant_id, email_id,
                           action_type, response, is_correct, timestamp
                    FROM participant_actions
                    WHERE campaign_id = ? AND participant_id = ?
                        AND email_id = ? AND action_type = 'answered'
                    """,
                    (campaign_id, participant_id, email_id),
                ).fetchone()
                if row is None:
                    return None
                action = dict(row)
                if action["is_correct"] is not None:
                    action["is_correct"] = bool(action["is_correct"])
                return action
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not retrieve participant feedback: {error}") from error

    def list_participant_actions(self, campaign_id, participant_id):
        try:
            with database_connection(self.database_path) as connection:
                rows = connection.execute(
                    """
                    SELECT action_id, campaign_id, participant_id, email_id,
                           action_type, response, is_correct, timestamp
                    FROM participant_actions
                    WHERE campaign_id = ? AND participant_id = ?
                    ORDER BY timestamp, action_id
                    """,
                    (campaign_id, participant_id),
                ).fetchall()
                actions = [dict(row) for row in rows]
                for action in actions:
                    if action["is_correct"] is not None:
                        action["is_correct"] = bool(action["is_correct"])
                return actions
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not list participant actions: {error}") from error

    def list_campaign_participants(self, campaign_id):
        try:
            with database_connection(self.database_path) as connection:
                rows = connection.execute(
                    """
                    SELECT p.participant_id, p.created_at,
                        SUM(CASE WHEN a.action_type = 'answered'
                            AND a.is_correct = 1 THEN 1 ELSE 0 END) AS correct_answers,
                        SUM(CASE WHEN a.action_type = 'answered'
                            AND a.is_correct = 0 THEN 1 ELSE 0 END) AS incorrect_answers,
                        MAX(CASE WHEN a.action_type = 'completed' THEN 1 ELSE 0 END)
                            AS completed
                    FROM participants AS p
                    JOIN participant_actions AS a
                        ON a.participant_id = p.participant_id
                    WHERE a.campaign_id = ? AND a.action_type IN ('joined', 'answered', 'completed')
                    GROUP BY p.participant_id
                    ORDER BY p.created_at DESC
                    """,
                    (campaign_id,),
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not list campaign participants: {error}") from error

    def create_campaign(
        self,
        campaign_id,
        campaign_name,
        description="",
        email_ids=None,
    ):
        if not all(
            isinstance(value, str) and value.strip()
            for value in (campaign_id, campaign_name)
        ):
            raise ValueError("Campaign ID and name must be non-empty strings.")
        if not isinstance(description, str):
            raise ValueError("Campaign description must be a string.")
        if len(campaign_name.strip()) > 100 or len(description) > 500:
            raise ValueError("Campaign name or description exceeds the allowed length.")

        now = utc_timestamp()
        try:
            with database_connection(self.database_path) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO campaigns (
                        campaign_id, campaign_name, description, status,
                        created_at, started_at, completed_at
                    ) VALUES (?, ?, ?, 'draft', ?, NULL, NULL)
                    """,
                    (campaign_id, campaign_name.strip(), description.strip(), now),
                )
                if email_ids is not None:
                    if not isinstance(email_ids, (list, tuple)) or not email_ids:
                        raise ValueError("Select at least one training email.")
                    selected_ids = list(
                        dict.fromkeys(
                            email_id.strip()
                            for email_id in email_ids
                            if isinstance(email_id, str) and email_id.strip()
                        )
                    )
                    if len(selected_ids) != len(email_ids):
                        raise ValueError("Training email IDs must be non-empty strings.")
                    for email_id in selected_ids:
                        if connection.execute(
                            "SELECT 1 FROM email_samples WHERE email_id = ?",
                            (email_id,),
                        ).fetchone() is None:
                            raise ValueError("One or more selected training emails do not exist.")
                    connection.executemany(
                        """
                        INSERT INTO campaign_email_assignments (
                            campaign_id, email_id, assigned_at
                        ) VALUES (?, ?, ?)
                        """,
                        [(campaign_id, email_id, now) for email_id in selected_ids],
                    )
                row = connection.execute(
                    """
                    SELECT campaign_id, campaign_name, description, status,
                           created_at, started_at, completed_at
                    FROM campaigns WHERE campaign_id = ?
                    """,
                    (campaign_id,),
                ).fetchone()
                connection.commit()
                return dict(row)
        except sqlite3.IntegrityError as error:
            raise EventStoreError(
                f"Could not create campaign '{campaign_id}': {error}"
            ) from error
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not create campaign: {error}") from error

    def update_campaign_status(self, campaign_id, status):
        if not isinstance(status, str) or status not in {"active", "paused", "completed"}:
            raise ValueError("Campaign status must be 'active', 'paused', or 'completed'.")

        now = utc_timestamp()
        try:
            with database_connection(self.database_path) as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT status FROM campaigns WHERE campaign_id = ?",
                    (campaign_id,),
                ).fetchone()
                if existing is None:
                    connection.rollback()
                    return None
                if existing["status"] == "completed":
                    raise ValueError("A completed campaign cannot be reopened.")

                if status == "paused":
                    if existing["status"] != "active":
                        raise ValueError("Only an active campaign can be paused.")
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO campaign_pauses (campaign_id, paused_at)
                        VALUES (?, ?)
                        """,
                        (campaign_id, now),
                    )
                elif status == "active":
                    connection.execute(
                        """
                        UPDATE campaigns
                        SET status = 'active',
                            started_at = COALESCE(started_at, ?)
                        WHERE campaign_id = ?
                        """,
                        (now, campaign_id),
                    )
                    connection.execute(
                        "DELETE FROM campaign_pauses WHERE campaign_id = ?",
                        (campaign_id,),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE campaigns
                        SET status = 'completed',
                            started_at = COALESCE(started_at, ?),
                            completed_at = ?
                        WHERE campaign_id = ?
                        """,
                        (now, now, campaign_id),
                    )
                    connection.execute(
                        "DELETE FROM campaign_pauses WHERE campaign_id = ?",
                        (campaign_id,),
                    )
                row = connection.execute(
                    """
                    SELECT c.campaign_id, c.campaign_name, c.description,
                           CASE WHEN p.campaign_id IS NOT NULL
                                THEN 'paused' ELSE c.status END AS status,
                           c.created_at, c.started_at, c.completed_at
                    FROM campaigns AS c
                    LEFT JOIN campaign_pauses AS p ON p.campaign_id = c.campaign_id
                    WHERE c.campaign_id = ?
                    """,
                    (campaign_id,),
                ).fetchone()
                connection.commit()
                return dict(row)
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not update campaign status: {error}") from error

    def list_campaigns(self):
        try:
            with database_connection(self.database_path) as connection:
                rows = connection.execute(
                    """
                    SELECT c.campaign_id, c.campaign_name, c.description,
                           CASE WHEN p.campaign_id IS NOT NULL
                                THEN 'paused' ELSE c.status END AS status,
                           c.created_at, c.started_at, c.completed_at
                    FROM campaigns AS c
                    LEFT JOIN campaign_pauses AS p ON p.campaign_id = c.campaign_id
                    ORDER BY c.created_at, c.campaign_id
                    """
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not list campaigns: {error}") from error

    def get_campaign(self, campaign_id):
        try:
            with database_connection(self.database_path) as connection:
                row = connection.execute(
                    """
                    SELECT c.campaign_id, c.campaign_name, c.description,
                           CASE WHEN p.campaign_id IS NOT NULL
                                THEN 'paused' ELSE c.status END AS status,
                           c.created_at, c.started_at, c.completed_at
                    FROM campaigns AS c
                    LEFT JOIN campaign_pauses AS p ON p.campaign_id = c.campaign_id
                    WHERE c.campaign_id = ?
                    """,
                    (campaign_id,),
                ).fetchone()
                return dict(row) if row is not None else None
        except sqlite3.Error as error:
            raise EventStoreError(f"Could not retrieve campaign: {error}") from error


class InMemoryEventStore:
    """Non-persistent adapter retained for isolated route/unit tests."""

    def __init__(self):
        self._events = []
        self._unique_events = {}
        self._lock = RLock()

    def record_once(self, campaign_id, email_id, participant_id, event_type):
        if event_type not in DATABASE_EVENT_TYPES:
            raise ValueError(f"Unsupported event type: {event_type}")

        key = (campaign_id, participant_id, email_id, event_type)
        with self._lock:
            existing_id = self._unique_events.get(key)
            if existing_id is not None:
                existing = self.get_event(existing_id)
                return dict(existing), False

            event = {
                "event_id": uuid4().hex,
                "campaign_id": campaign_id,
                "email_id": email_id,
                "participant_id": participant_id,
                "event_type": event_type,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            self._events.append(event)
            self._unique_events[key] = event["event_id"]
            return dict(event), True

    def get_event(self, event_id):
        with self._lock:
            for event in self._events:
                if event["event_id"] == event_id:
                    return dict(event)
        return None

    def list_events(self, limit=1000, campaign_id=None, email_id=None):
        if not isinstance(limit, int) or not 1 <= limit <= 10000:
            raise ValueError("Event list limit must be between 1 and 10000.")
        with self._lock:
            events = list(reversed(self._events))
            if campaign_id is not None:
                events = [
                    event for event in events
                    if event["campaign_id"] == campaign_id
                ]
            if email_id is not None:
                events = [event for event in events if event["email_id"] == email_id]
            return [dict(event) for event in events[:limit]]

    def summary(self, campaign_id=None):
        with self._lock:
            events = self._events
            if campaign_id is not None:
                events = [
                    event for event in events
                    if event["campaign_id"] == campaign_id
                ]
            counts = {"open": 0, "click": 0, "report": 0}
            participants = set()
            for event in events:
                counts[event["event_type"]] += 1
                participants.add(event["participant_id"])
            return {
                "opened": counts["open"],
                "clicks": counts["click"],
                "reports": counts["report"],
                "unique_participants": len(participants),
                "total_events": len(events),
            }

    def campaign_statistics(self, campaign_id):
        return self.summary(campaign_id=campaign_id)

    def list_campaigns(self):
        return [
            {
                "campaign_id": DEFAULT_CAMPAIGN_ID,
                "campaign_name": "PhishShield Local Training Campaign",
                "description": "In-memory campaign used only by isolated tests.",
                "status": "active",
                "created_at": "",
                "started_at": "",
                "completed_at": None,
            }
        ]


def _make_idempotency_key(campaign_id, email_id, participant_id, event_type):
    raw_key = "\0".join((campaign_id, email_id, participant_id, event_type))
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _make_action_key(campaign_id, participant_id, action_type, email_id):
    raw_key = "\0".join((campaign_id, participant_id, action_type, email_id))
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _application_event(row):
    event = dict(row)
    event["event_type"] = APPLICATION_EVENT_TYPES[event["event_type"]]
    return event
