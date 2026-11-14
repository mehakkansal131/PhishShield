import json
import tempfile
import unittest
from pathlib import Path

from research.validate_dataset import validate_dataset
from simulation.campaign_service import DEFAULT_DATASET_PATH, load_campaigns


class ResearchDatasetTests(unittest.TestCase):
    def test_existing_dataset_passes_validator_and_campaign_loader(self):
        counts = validate_dataset()
        samples = load_campaigns(DEFAULT_DATASET_PATH)

        self.assertEqual(counts, {"phishing": 5, "legitimate": 5})
        self.assertEqual(len(samples), 10)
        self.assertEqual(len({sample["email_id"] for sample in samples}), 10)
        self.assertTrue(all(isinstance(sample["email_body"], str) for sample in samples))

    def test_validator_rejects_missing_fields_and_invalid_labels(self):
        valid_sample = json.loads(
            DEFAULT_DATASET_PATH.read_text(encoding="utf-8")
        )[0]
        invalid_sample = dict(valid_sample)
        invalid_sample.pop("subject")
        with tempfile.TemporaryDirectory() as temporary_directory:
            dataset_path = Path(temporary_directory) / "samples.json"
            dataset_path.write_text(
                json.dumps([invalid_sample] * 10),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "missing fields"):
                validate_dataset(dataset_path)

            invalid_sample["subject"] = "Practice subject"
            invalid_sample["email_type"] = "unknown"
            dataset_path.write_text(
                json.dumps([invalid_sample] * 10),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "invalid email_type"):
                validate_dataset(dataset_path)


if __name__ == "__main__":
    unittest.main()
