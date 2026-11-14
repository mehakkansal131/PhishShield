"""Reproducible evaluation of the detector against labelled JSON samples."""

import json
from pathlib import Path

from detection.scorer import PhishingDetector
from simulation.campaign_service import DEFAULT_DATASET_PATH


ALLOWED_LABELS = {"phishing", "legitimate"}


def load_labeled_dataset(path=DEFAULT_DATASET_PATH):
    """Load a JSON list and verify the fields needed for smoke-test evaluation."""
    try:
        with Path(path).open(encoding="utf-8") as dataset_file:
            samples = json.load(dataset_file)
    except (OSError, json.JSONDecodeError, UnicodeError) as error:
        raise ValueError(f"Could not load labelled JSON dataset: {error}") from error
    if not isinstance(samples, list):
        raise ValueError("The labelled dataset must be a JSON list.")
    if not samples:
        raise ValueError("The labelled dataset contains no samples.")

    for index, sample in enumerate(samples, start=1):
        if not isinstance(sample, dict):
            raise ValueError(f"Dataset item {index} must be an object.")
        label = sample.get("email_type")
        if label not in ALLOWED_LABELS:
            raise ValueError(
                f"Dataset item {index} has unsupported label {label!r}."
            )
        if not isinstance(sample.get("email_id"), str):
            raise ValueError(f"Dataset item {index} has no string email_id.")
    return samples


def evaluate_dataset(samples, detector=None):
    """Calculate binary metrics with 'Likely Phishing' as the positive class."""
    if not samples:
        raise ValueError("At least one labelled sample is required.")
    labels = {sample.get("email_type") for sample in samples}
    if not labels <= ALLOWED_LABELS:
        raise ValueError("Samples contain labels outside phishing/legitimate.")
    if labels != ALLOWED_LABELS:
        return {
            "available": False,
            "limitation": "Evaluation requires both phishing and legitimate examples.",
            "sample_count": len(samples),
        }

    engine = detector or PhishingDetector()
    matrix = {
        "true_positive": 0,
        "false_positive": 0,
        "true_negative": 0,
        "false_negative": 0,
    }
    predictions = []
    false_positives = []
    false_negatives = []

    for sample in samples:
        actual = sample["email_type"]
        result = engine.analyze(sample)
        predicted = result["predicted_class"]
        predictions.append(
            {
                "email_id": sample["email_id"],
                "actual": actual,
                "predicted": predicted,
                "risk_score": result["risk_score"],
                "verdict": result["verdict"],
            }
        )
        if actual == "phishing" and predicted == "phishing":
            matrix["true_positive"] += 1
        elif actual == "legitimate" and predicted == "phishing":
            matrix["false_positive"] += 1
            false_positives.append(sample["email_id"])
        elif actual == "legitimate" and predicted == "legitimate":
            matrix["true_negative"] += 1
        else:
            matrix["false_negative"] += 1
            false_negatives.append(sample["email_id"])

    total = len(samples)
    precision = _divide(
        matrix["true_positive"],
        matrix["true_positive"] + matrix["false_positive"],
    )
    recall = _divide(
        matrix["true_positive"],
        matrix["true_positive"] + matrix["false_negative"],
    )
    f1 = _divide(2 * precision * recall, precision + recall)
    return {
        "available": True,
        "sample_count": total,
        "class_counts": {
            label: sum(sample["email_type"] == label for sample in samples)
            for label in sorted(ALLOWED_LABELS)
        },
        "confusion_matrix": matrix,
        "accuracy": _divide(
            matrix["true_positive"] + matrix["true_negative"], total
        ),
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "predictions": predictions,
        "limitation": (
            "This small labelled set is a reproducible smoke test, not evidence "
            "of real-world detection accuracy."
        ),
    }


def format_evaluation_report(result):
    """Create a concise, readable terminal report."""
    lines = ["PhishShield detector evaluation"]
    if not result["available"]:
        lines.extend(
            [
                f"Samples: {result['sample_count']}",
                f"Evaluation unavailable: {result['limitation']}",
            ]
        )
        return "\n".join(lines)

    matrix = result["confusion_matrix"]
    lines.extend(
        [
            f"Samples: {result['sample_count']}",
            f"Actual classes: phishing={result['class_counts']['phishing']}, "
            f"legitimate={result['class_counts']['legitimate']}",
            "",
            "Confusion matrix (actual rows, predicted columns):",
            "                    Predicted phishing  Predicted legitimate",
            f"Actual phishing     {matrix['true_positive']:>18}  {matrix['false_negative']:>20}",
            f"Actual legitimate  {matrix['false_positive']:>18}  {matrix['true_negative']:>20}",
            "",
            f"Accuracy:  {result['accuracy']:.3f}",
            f"Precision: {result['precision']:.3f}",
            f"Recall:    {result['recall']:.3f}",
            f"F1-score:  {result['f1_score']:.3f}",
            f"False positives: {', '.join(result['false_positives']) or 'none'}",
            f"False negatives: {', '.join(result['false_negatives']) or 'none'}",
            f"Limitation: {result['limitation']}",
        ]
    )
    return "\n".join(lines)


def print_evaluation_report(path=DEFAULT_DATASET_PATH, detector=None):
    samples = load_labeled_dataset(path)
    result = evaluate_dataset(samples, detector=detector)
    print(format_evaluation_report(result))
    return result


def _divide(numerator, denominator):
    return numerator / denominator if denominator else 0.0
