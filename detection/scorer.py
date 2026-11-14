"""Risk scoring and the public detection-engine interface."""

from dataclasses import dataclass, field
from pathlib import Path

from detection.email_parser import (
    normalize_email_input,
    parse_eml_bytes,
    parse_eml_file,
    parse_raw_email,
)
from detection.rules import run_detection_rules


DEFAULT_WEIGHTS = {
    "sender_display_name_mismatch": 15,
    "reply_to_mismatch": 18,
    "url_risk": 24,
    "urgency_or_threat": 14,
    "sensitive_information_request": 22,
    "linked_action_context": 25,
    "attachment_metadata": 18,
    "email_authentication": 14,
}


@dataclass(frozen=True)
class DetectionConfig:
    """Weights and score thresholds; scores are heuristic, not probabilities."""

    weights: dict = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    medium_threshold: int = 25
    high_threshold: int = 55

    def __post_init__(self):
        if not 0 <= self.medium_threshold < self.high_threshold <= 100:
            raise ValueError("Thresholds must satisfy 0 <= medium < high <= 100.")
        if any(
            not isinstance(value, int) or value < 0
            for value in self.weights.values()
        ):
            raise ValueError("Every detection weight must be a non-negative integer.")


class PhishingDetector:
    """Analyze structured records, raw email text, .eml bytes, or local .eml paths."""

    def __init__(self, config=None):
        self.config = config or DetectionConfig()

    def analyze(self, email):
        """Return a structured, explainable result without contacting URLs/files."""
        normalized = self._normalize_input(email)
        rule_results = run_detection_rules(normalized)
        score = 0
        reasons = []
        extracted_urls = []
        for result in rule_results:
            if result["name"] == "url_risk":
                extracted_urls = result.get("urls", [])
            if result["outcome"] == "detected":
                contribution = self.config.weights.get(result["name"], 0)
                result["score_contribution"] = contribution
                score += contribution
                reasons.append(
                    {
                        "rule": result["name"],
                        "explanation": result["explanation"],
                        "details": result.get("details", []),
                    }
                )
            elif result["outcome"] == "not_detected":
                result["score_contribution"] = 0
            else:
                result["score_contribution"] = 0

        score = min(100, max(0, score))
        if score >= self.config.high_threshold:
            risk_level = "High"
            verdict = "Likely Phishing"
        elif score >= self.config.medium_threshold:
            risk_level = "Medium"
            verdict = "Suspicious"
        else:
            risk_level = "Low"
            verdict = "Likely Legitimate"

        limitations = [
            "The risk score is a heuristic, not a calibrated probability.",
            "Parsing does not verify sender identity or whether message content is safe.",
            "URLs and attachment names are analyzed as text/metadata only; nothing is opened or contacted.",
        ]
        if normalized.get("source") == "eml":
            limitations.append(
                "Authentication-Results headers are treated as untrusted unless the caller explicitly marks receiver evidence trusted."
            )
        if any(result["outcome"] == "unavailable" for result in rule_results):
            limitations.append(
                "Some checks were unavailable because the relevant fields or evidence were not supplied."
            )

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "verdict": verdict,
            "predicted_class": "phishing" if verdict == "Likely Phishing" else (
                "legitimate" if verdict == "Likely Legitimate" else "phishing"
            ),
            "reasons": reasons,
            "rule_results": rule_results,
            "sender": {
                "display_name": normalized["sender_display_name"],
                "email": normalized["sender_email"],
                "reply_to": normalized["reply_to"],
            },
            "subject": normalized["subject"],
            "urls": extracted_urls,
            "limitations": limitations,
        }

    def _normalize_input(self, email):
        if isinstance(email, dict):
            return normalize_email_input(email)
        if isinstance(email, bytes):
            return normalize_email_input(parse_eml_bytes(email))
        if isinstance(email, Path):
            return normalize_email_input(parse_eml_file(email))
        if isinstance(email, str):
            return normalize_email_input(parse_raw_email(email))
        raise TypeError(
            "Email input must be a structured dictionary, text, bytes, or .eml path."
        )
