"""Dataset loading and safe preparation for participant-facing pages."""

import json
from pathlib import Path


DEFAULT_DATASET_PATH = (
    Path(__file__).resolve().parents[1]
    / "research"
    / "data"
    / "sample_emails.json"
)
LABELS = {"phishing", "legitimate"}
CORE_FIELDS = {
    "email_id",
    "email_type",
    "scenario",
    "subject",
    "sender_display_name",
    "sender_email",
    "reply_to",
    "email_body",
}


class CampaignDataError(ValueError):
    """Raised when the Module 1 campaign dataset cannot be used."""


def load_campaigns(path=None):
    dataset_path = Path(path) if path is not None else DEFAULT_DATASET_PATH
    try:
        with dataset_path.open(encoding="utf-8") as dataset_file:
            data = json.load(dataset_file)
    except OSError as error:
        raise CampaignDataError(
            f"Dataset file was not found or could not be read: {dataset_path}"
        ) from error
    except json.JSONDecodeError as error:
        raise CampaignDataError(
            f"Dataset contains invalid JSON at line {error.lineno}, "
            f"column {error.colno}: {dataset_path}"
        ) from error
    except UnicodeError as error:
        raise CampaignDataError(
            f"Dataset is not valid UTF-8 text: {dataset_path}"
        ) from error

    if not isinstance(data, list):
        raise CampaignDataError("Dataset must contain a JSON list of email objects.")

    samples = []
    seen_ids = set()
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise CampaignDataError(f"Dataset item {index} must be a JSON object.")

        missing_fields = CORE_FIELDS - item.keys()
        if missing_fields:
            raise CampaignDataError(
                f"Dataset item {index} is missing required fields: "
                f"{', '.join(sorted(missing_fields))}."
            )

        for field in CORE_FIELDS:
            if not isinstance(item[field], str) or not item[field].strip():
                raise CampaignDataError(
                    f"Dataset item {index} field '{field}' must be a non-empty string."
                )

        if item["email_type"] not in LABELS:
            raise CampaignDataError(
                f"Dataset item {index} has unsupported email_type "
                f"'{item['email_type']}'."
            )

        email_id = item["email_id"]
        if email_id in seen_ids:
            raise CampaignDataError(f"Dataset contains duplicate email_id '{email_id}'.")
        seen_ids.add(email_id)

        indicators = item.get("suspicious_indicators", [])
        if not isinstance(indicators, list) or not all(
            isinstance(indicator, str) for indicator in indicators
        ):
            raise CampaignDataError(
                f"Dataset item {index} field 'suspicious_indicators' "
                "must be a list of strings."
            )

        normalized = dict(item)
        normalized["psychological_trigger"] = item.get(
            "psychological_trigger", "Not specified"
        )
        normalized["suspicious_indicators"] = indicators
        normalized["expected_detection_reason"] = item.get(
            "expected_detection_reason", "No instructor note was provided."
        )
        normalized["recommended_user_action"] = item.get(
            "recommended_user_action", "Verify unexpected requests independently."
        )
        samples.append(normalized)

    if not samples:
        raise CampaignDataError("Dataset contains no campaign samples.")
    return samples


def public_sample(sample):
    """Remove labels and analysis fields from participant-facing views."""
    public_fields = (
        "email_id",
        "scenario",
        "subject",
        "sender_display_name",
        "sender_email",
        "reply_to",
        "email_body",
    )
    return {field: sample[field] for field in public_fields}
