"""Validate the PhishShield Module 1 sample-email dataset."""

import json
from pathlib import Path


DATASET_PATH = Path(__file__).parent / "data" / "sample_emails.json"
REQUIRED_FIELDS = {
    "email_id",
    "email_type",
    "scenario",
    "subject",
    "sender_display_name",
    "sender_email",
    "reply_to",
    "email_body",
    "psychological_trigger",
    "suspicious_indicators",
    "expected_detection_reason",
    "recommended_user_action",
}
LABELS = {"phishing", "legitimate"}
STRING_FIELDS = REQUIRED_FIELDS - {"suspicious_indicators"}


def validate_dataset(path=DATASET_PATH):
    """Load and validate the dataset; raise ValueError with useful details."""
    try:
        with path.open(encoding="utf-8") as dataset_file:
            samples = json.load(dataset_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read valid JSON from {path}: {error}") from error

    if not isinstance(samples, list):
        raise ValueError("The top-level JSON value must be a list.")

    ids = set()
    label_counts = {label: 0 for label in LABELS}

    for index, sample in enumerate(samples, start=1):
        if not isinstance(sample, dict):
            raise ValueError(f"Sample {index} must be a JSON object.")

        missing_fields = REQUIRED_FIELDS - sample.keys()
        extra_fields = sample.keys() - REQUIRED_FIELDS
        if missing_fields:
            raise ValueError(
                f"Sample {index} is missing fields: {', '.join(sorted(missing_fields))}"
            )
        if extra_fields:
            raise ValueError(
                f"Sample {index} has unexpected fields: {', '.join(sorted(extra_fields))}"
            )

        for field in STRING_FIELDS:
            if not isinstance(sample[field], str) or not sample[field].strip():
                raise ValueError(
                    f"Sample {index} field '{field}' must be a non-empty string."
                )

        indicators = sample["suspicious_indicators"]
        if not isinstance(indicators, list) or not all(
            isinstance(item, str) for item in indicators
        ):
            raise ValueError(
                f"Sample {index} field 'suspicious_indicators' must be a list of strings."
            )

        email_id = sample["email_id"]
        if email_id in ids:
            raise ValueError(f"Duplicate email_id: {email_id}")
        ids.add(email_id)

        label = sample["email_type"]
        if label not in LABELS:
            raise ValueError(
                f"Sample {index} has invalid email_type '{label}'; "
                f"allowed labels are: {', '.join(sorted(LABELS))}."
            )
        label_counts[label] += 1

    if len(samples) != 10:
        raise ValueError(f"Expected exactly 10 samples; found {len(samples)}.")
    if label_counts != {"phishing": 5, "legitimate": 5}:
        raise ValueError(
            "Expected 5 phishing and 5 legitimate samples; "
            f"found {label_counts['phishing']} phishing and "
            f"{label_counts['legitimate']} legitimate."
        )

    return label_counts


def main():
    counts = validate_dataset()
    print(
        "Validation passed: 10 samples "
        f"({counts['phishing']} phishing, {counts['legitimate']} legitimate)."
    )
    print("All required fields, labels, IDs, and JSON structures are valid.")


if __name__ == "__main__":
    main()
