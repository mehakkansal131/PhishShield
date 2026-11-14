import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import create_app
from simulation.campaign_service import DEFAULT_DATASET_PATH, load_campaigns
from simulation.database import (
    DEFAULT_CAMPAIGN_ID,
    DatabaseInitializationError,
    database_connection,
    initialize_database,
)
from simulation.event_store import EventStoreError, SQLiteEventStore


class SQLiteEventStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "instance" / "phishshield.db"
        self.samples = load_campaigns(DEFAULT_DATASET_PATH)
        self.store = SQLiteEventStore(self.database_path, self.samples)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_database_initialization_creates_schema_and_seeds_once(self):
        self.assertTrue(self.database_path.is_file())
        initialize_database(self.database_path, self.samples)
        initialize_database(self.database_path, self.samples)

        with database_connection(self.database_path) as connection:
            campaign_count = connection.execute(
                "SELECT COUNT(*) FROM campaigns"
            ).fetchone()[0]
            sample_count = connection.execute(
                "SELECT COUNT(*) FROM email_samples"
            ).fetchone()[0]
            event_count = connection.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]

        self.assertEqual(campaign_count, 1)
        self.assertEqual(sample_count, 10)
        self.assertEqual(event_count, 0)
        self.assertEqual(self.store.get_campaign(DEFAULT_CAMPAIGN_ID)["status"], "active")

    def test_existing_unversioned_database_is_backed_up_before_additive_migration(self):
        legacy_path = Path(self.temporary_directory.name) / "legacy.sqlite"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                "CREATE TABLE preserved_record (value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO preserved_record (value) VALUES (?)",
                ("keep-this-record",),
            )
            connection.commit()
        finally:
            connection.close()
        initialize_database(legacy_path, self.samples)

        backup_path = Path(f"{legacy_path}.pre-v1.bak")
        self.assertTrue(backup_path.is_file())
        backup = sqlite3.connect(backup_path)
        try:
            self.assertEqual(
                backup.execute("SELECT value FROM preserved_record").fetchone()[0],
                "keep-this-record",
            )
        finally:
            backup.close()
        with database_connection(legacy_path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(
                connection.execute("SELECT value FROM preserved_record").fetchone()[0],
                "keep-this-record",
            )

    def test_existing_incomplete_backup_stops_migration_without_changing_database(self):
        legacy_path = Path(self.temporary_directory.name) / "legacy-with-backup.sqlite"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                "CREATE TABLE preserved_record (value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO preserved_record (value) VALUES (?)",
                ("keep-this-record",),
            )
            connection.commit()
        finally:
            connection.close()
        backup_path = Path(f"{legacy_path}.pre-v1.bak")
        backup_path.touch()

        with self.assertRaises(DatabaseInitializationError):
            initialize_database(legacy_path, self.samples)

        connection = sqlite3.connect(legacy_path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(
                connection.execute("SELECT value FROM preserved_record").fetchone()[0],
                "keep-this-record",
            )
            self.assertEqual(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name='campaign_email_assignments'"
                ).fetchone(),
                None,
            )
        finally:
            connection.close()

    def test_metadata_seeding_does_not_store_email_body(self):
        with database_connection(self.database_path) as connection:
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(email_samples)")
            }
        self.assertNotIn("email_body", columns)

    def test_event_types_are_persisted_using_database_vocabulary(self):
        events = []
        for event_type in ("open", "click", "report"):
            event, created = self.store.record_once(
                DEFAULT_CAMPAIGN_ID,
                "PS-PH-001",
                f"participant-{event_type}",
                event_type,
            )
            self.assertTrue(created)
            events.append(event)

        self.assertEqual(
            {event["event_type"] for event in events},
            {"open", "click", "report"},
        )
        with database_connection(self.database_path) as connection:
            stored_types = {
                row["event_type"]
                for row in connection.execute("SELECT event_type FROM events")
            }
        self.assertEqual(stored_types, {"displayed", "clicked", "reported"})

    def test_duplicate_actions_are_idempotent_after_store_recreation(self):
        first, created = self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "click"
        )
        reopened_store = SQLiteEventStore(self.database_path, self.samples)
        repeated, created_again = reopened_store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "click"
        )

        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first["event_id"], repeated["event_id"])
        self.assertEqual(reopened_store.summary()["clicks"], 1)

    def test_events_survive_application_restart(self):
        event, _created = self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-002", "participant-a", "open"
        )
        restarted_app = create_app(
            database_path=self.database_path,
            secret_key="database-restart-test",
        )
        restarted_store = restarted_app.extensions["event_store"]

        self.assertEqual(restarted_store.get_event(event["event_id"]), event)
        self.assertEqual(restarted_store.summary()["opened"], 1)

    def test_event_statistics_and_filters(self):
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "open"
        )
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "click"
        )
        self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-002", "participant-b", "report"
        )

        statistics = self.store.campaign_statistics(DEFAULT_CAMPAIGN_ID)
        self.assertEqual(statistics["opened"], 1)
        self.assertEqual(statistics["clicks"], 1)
        self.assertEqual(statistics["reports"], 1)
        self.assertEqual(statistics["unique_participants"], 2)
        self.assertEqual(
            len(self.store.list_events(campaign_id=DEFAULT_CAMPAIGN_ID, email_id="PS-PH-001")),
            2,
        )
        self.assertIsNone(self.store.campaign_statistics("unknown-campaign"))

    def test_foreign_key_enforcement_and_reject_unknown_references(self):
        with database_connection(self.database_path) as connection:
            self.assertEqual(
                connection.execute("PRAGMA foreign_keys").fetchone()[0],
                1,
            )

        with self.assertRaises(EventStoreError):
            self.store.record_once(
                DEFAULT_CAMPAIGN_ID,
                "unknown-email",
                "participant-a",
                "open",
            )

    def test_timestamps_are_utc_iso_format(self):
        event, _created = self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "open"
        )
        self.assertTrue(event["timestamp"].endswith("+00:00"))

    def test_parameterized_filters_do_not_change_query_structure(self):
        event, _created = self.store.record_once(
            DEFAULT_CAMPAIGN_ID, "PS-PH-001", "participant-a", "open"
        )
        filtered = self.store.list_events(
            campaign_id="module-2-local' OR 1=1 --"
        )
        self.assertEqual(filtered, [])
        self.assertIsNotNone(self.store.get_event(event["event_id"]))

    def test_invalid_database_event_type_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported event type"):
            self.store.record_once(
                DEFAULT_CAMPAIGN_ID,
                "PS-PH-001",
                "participant-a",
                "delete",
            )

    def test_create_campaign_and_move_it_through_statuses(self):
        created = self.store.create_campaign(
            "classroom-demo-2",
            "Second Classroom Campaign",
            "A second fictional campaign for service testing.",
        )
        self.assertEqual(created["status"], "draft")
        self.assertIsNone(created["started_at"])

        active = self.store.update_campaign_status("classroom-demo-2", "active")
        self.assertEqual(active["status"], "active")
        self.assertIsNotNone(active["started_at"])

        completed = self.store.update_campaign_status(
            "classroom-demo-2", "completed"
        )
        self.assertEqual(completed["status"], "completed")
        self.assertIsNotNone(completed["completed_at"])

        with self.assertRaisesRegex(ValueError, "cannot be reopened"):
            self.store.update_campaign_status("classroom-demo-2", "active")

    def test_campaign_creation_rejects_duplicate_and_unknown_status(self):
        self.store.create_campaign("classroom-demo-2", "Second Campaign")
        with self.assertRaises(EventStoreError):
            self.store.create_campaign("classroom-demo-2", "Duplicate Campaign")
        with self.assertRaisesRegex(ValueError, "status must be"):
            self.store.update_campaign_status("classroom-demo-2", "draft")


class DatabaseForeignKeyTests(unittest.TestCase):
    def test_each_connection_enables_foreign_keys(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "phishshield.db"
            initialize_database(database_path, load_campaigns())

            for _ in range(2):
                with database_connection(database_path) as connection:
                    self.assertEqual(
                        connection.execute("PRAGMA foreign_keys").fetchone()[0],
                        1,
                    )


if __name__ == "__main__":
    unittest.main()
