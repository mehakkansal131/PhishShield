import unittest

from simulation.event_store import InMemoryEventStore


class InMemoryEventStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryEventStore()

    def test_action_is_unique_for_participant_sample_and_type(self):
        first, created = self.store.record_once(
            "campaign-a", "PS-PH-001", "participant-a", "click"
        )
        repeated, created_again = self.store.record_once(
            "campaign-a", "PS-PH-001", "participant-a", "click"
        )

        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first["event_id"], repeated["event_id"])
        self.assertEqual(self.store.summary()["clicks"], 1)

    def test_different_action_types_are_counted_separately(self):
        self.store.record_once("campaign-a", "PS-PH-001", "participant-a", "open")
        self.store.record_once("campaign-a", "PS-PH-001", "participant-a", "report")

        summary = self.store.summary()
        self.assertEqual(summary["opened"], 1)
        self.assertEqual(summary["reports"], 1)
        self.assertEqual(summary["unique_participants"], 1)
        self.assertEqual(summary["total_events"], 2)

    def test_unknown_event_type_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported event type"):
            self.store.record_once(
                "campaign-a", "PS-PH-001", "participant-a", "password"
            )


if __name__ == "__main__":
    unittest.main()
