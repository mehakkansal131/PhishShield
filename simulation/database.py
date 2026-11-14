"""SQLite schema and seed-data initialization for PhishShield."""

import os
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_CAMPAIGN_ID = "module-2-local"
DEFAULT_CAMPAIGN_NAME = "PhishShield Local Training Campaign"
DEFAULT_CAMPAIGN_DESCRIPTION = (
    "Default local classroom campaign using the fictional Module 1 email samples."
)
DATABASE_SCHEMA_VERSION = 1

SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS campaigns (
        campaign_id TEXT PRIMARY KEY,
        campaign_name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'draft'
            CHECK (status IN ('draft', 'active', 'completed')),
        created_at TEXT NOT NULL,
        started_at TEXT,
        completed_at TEXT,
        CHECK (
            (status != 'completed' OR completed_at IS NOT NULL)
            AND (status != 'active' OR started_at IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS email_samples (
        email_id TEXT PRIMARY KEY,
        email_type TEXT NOT NULL CHECK (email_type IN ('phishing', 'legitimate')),
        scenario TEXT NOT NULL,
        subject TEXT NOT NULL,
        sender_display_name TEXT NOT NULL,
        sender_email TEXT NOT NULL,
        reply_to TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS participants (
        participant_id TEXT PRIMARY KEY,
        display_name TEXT,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        email_id TEXT NOT NULL REFERENCES email_samples(email_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        participant_id TEXT NOT NULL REFERENCES participants(participant_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        event_type TEXT NOT NULL
            CHECK (event_type IN ('displayed', 'clicked', 'reported')),
        timestamp TEXT NOT NULL,
        session_event_key TEXT NOT NULL UNIQUE,
        UNIQUE (campaign_id, email_id, participant_id, event_type)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_campaign_timestamp ON events(campaign_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_email ON events(email_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_participant ON events(participant_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
    """
    CREATE TABLE IF NOT EXISTS campaign_email_assignments (
        campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        email_id TEXT NOT NULL REFERENCES email_samples(email_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        assigned_at TEXT NOT NULL,
        PRIMARY KEY (campaign_id, email_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS campaign_pauses (
        campaign_id TEXT PRIMARY KEY REFERENCES campaigns(campaign_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        paused_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS participant_actions (
        action_id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        participant_id TEXT NOT NULL REFERENCES participants(participant_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        email_id TEXT REFERENCES email_samples(email_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        action_type TEXT NOT NULL
            CHECK (action_type IN ('joined', 'answered', 'completed')),
        response TEXT
            CHECK (response IS NULL OR response IN ('phishing', 'legitimate', 'clicked')),
        is_correct INTEGER CHECK (is_correct IS NULL OR is_correct IN (0, 1)),
        timestamp TEXT NOT NULL,
        action_key TEXT NOT NULL UNIQUE,
        CHECK (
            (action_type = 'joined' AND email_id IS NULL AND response IS NULL AND is_correct IS NULL)
            OR (action_type = 'answered' AND email_id IS NOT NULL AND response IS NOT NULL)
            OR (action_type = 'completed' AND email_id IS NULL AND response IS NULL AND is_correct IS NULL)
        )
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_participant_actions_campaign_time ON participant_actions(campaign_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_participant_actions_participant ON participant_actions(participant_id)",
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_participant_answer_once
    ON participant_actions(campaign_id, participant_id, email_id)
    WHERE action_type = 'answered'
    """,
)


class DatabaseInitializationError(RuntimeError):
    """Raised when PhishShield's SQLite database cannot be initialized."""


def utc_timestamp():
    """Return a timezone-aware ISO-8601 timestamp in UTC."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def database_connection(database_path):
    """Open a SQLite connection with foreign-key checks enabled."""
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        enabled = connection.execute("PRAGMA foreign_keys").fetchone()[0]
        if enabled != 1:
            raise DatabaseInitializationError(
                "SQLite foreign-key enforcement could not be enabled."
            )
        yield connection
    finally:
        connection.close()


def _create_migration_backup(database_path, backup_path, expected_version):
    """Create and verify a complete backup before publishing its final path."""
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{backup_path.name}.",
        suffix=".tmp",
        dir=backup_path.parent,
    )
    os.close(file_descriptor)
    temporary_path = Path(temporary_name)
    try:
        source = sqlite3.connect(database_path)
        backup = sqlite3.connect(temporary_path)
        try:
            source.backup(backup)
            integrity = backup.execute("PRAGMA integrity_check").fetchone()[0]
            backup_version = backup.execute("PRAGMA user_version").fetchone()[0]
        finally:
            backup.close()
            source.close()
        if integrity != "ok" or backup_version != expected_version:
            raise DatabaseInitializationError(
                "The pre-migration database backup failed verification."
            )
        os.link(temporary_path, backup_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def initialize_database(
    database_path,
    email_samples,
    campaign_id=DEFAULT_CAMPAIGN_ID,
):
    """Create the schema and idempotently seed campaign and email metadata."""
    try:
        path = Path(database_path)
        if path.is_file():
            source = sqlite3.connect(path)
            try:
                previous_version = source.execute(
                    "PRAGMA user_version"
                ).fetchone()[0]
            finally:
                source.close()
            if previous_version < DATABASE_SCHEMA_VERSION:
                backup_path = Path(f"{path}.pre-v{DATABASE_SCHEMA_VERSION}.bak")
                if backup_path.exists():
                    raise DatabaseInitializationError(
                        f"Migration backup already exists; refusing to overwrite or trust it: "
                        f"{backup_path}"
                    )
                _create_migration_backup(path, backup_path, previous_version)

        with database_connection(database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            current_version = connection.execute(
                "PRAGMA user_version"
            ).fetchone()[0]
            if current_version > DATABASE_SCHEMA_VERSION:
                raise DatabaseInitializationError(
                    "The database schema is newer than this PhishShield version."
                )
            for statement in SCHEMA_STATEMENTS:
                connection.execute(statement)

            now = utc_timestamp()
            connection.execute(
                """
                INSERT OR IGNORE INTO campaigns (
                    campaign_id, campaign_name, description, status,
                    created_at, started_at
                ) VALUES (?, ?, ?, 'active', ?, ?)
                """,
                (
                    campaign_id,
                    DEFAULT_CAMPAIGN_NAME,
                    DEFAULT_CAMPAIGN_DESCRIPTION,
                    now,
                    now,
                ),
            )

            connection.executemany(
                """
                INSERT INTO email_samples (
                    email_id, email_type, scenario, subject,
                    sender_display_name, sender_email, reply_to, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(email_id) DO UPDATE SET
                    email_type = excluded.email_type,
                    scenario = excluded.scenario,
                    subject = excluded.subject,
                    sender_display_name = excluded.sender_display_name,
                    sender_email = excluded.sender_email,
                    reply_to = excluded.reply_to
                """,
                [
                    (
                        sample["email_id"],
                        sample["email_type"],
                        sample["scenario"],
                        sample["subject"],
                        sample["sender_display_name"],
                        sample["sender_email"],
                        sample["reply_to"],
                        now,
                    )
                    for sample in email_samples
                ],
            )
            connection.executemany(
                """
                INSERT OR IGNORE INTO campaign_email_assignments (
                    campaign_id, email_id, assigned_at
                ) VALUES (?, ?, ?)
                """,
                [
                    (campaign_id, sample["email_id"], now)
                    for sample in email_samples
                ],
            )
            connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")
            connection.commit()
    except (sqlite3.Error, OSError, KeyError, TypeError) as error:
        if isinstance(error, DatabaseInitializationError):
            raise
        raise DatabaseInitializationError(
            f"Could not initialize the PhishShield database: {error}"
        ) from error
