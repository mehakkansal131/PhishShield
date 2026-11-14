import tempfile
import unittest
from pathlib import Path

from detection.email_parser import (
    extract_html_content,
    normalize_email_input,
    parse_eml_bytes,
    parse_eml_file,
    parse_raw_email,
)
from detection.evaluator import (
    evaluate_dataset,
    format_evaluation_report,
    load_labeled_dataset,
)
from detection.scorer import DetectionConfig, PhishingDetector
from simulation.campaign_service import DEFAULT_DATASET_PATH


def suspicious_email():
    return {
        "email_id": "TEST-PHISH",
        "email_type": "phishing",
        "scenario": "Fictional account notice",
        "subject": "Urgent: account suspension today",
        "sender_display_name": "Campus Security Support",
        "sender_email": "billing@unrelated-mail.test",
        "reply_to": "responses@other-mail.test",
        "email_body": (
            "Your account will be suspended today. Reply with your password "
            "and OTP to restore access. Visit "
            "https://192.0.2.10/verify"
        ),
        "attachments": [{"filename": "notice.js"}],
    }


class DetectionScorerTests(unittest.TestCase):
    def setUp(self):
        self.detector = PhishingDetector()

    def test_clearly_suspicious_message_has_explainable_high_risk(self):
        result = self.detector.analyze(suspicious_email())

        self.assertGreaterEqual(result["risk_score"], 55)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertEqual(result["risk_level"], "High")
        self.assertEqual(result["verdict"], "Likely Phishing")
        rule_names = {reason["rule"] for reason in result["reasons"]}
        self.assertIn("reply_to_mismatch", rule_names)
        self.assertIn("url_risk", rule_names)
        self.assertIn("sensitive_information_request", rule_names)
        self.assertIn("attachment_metadata", rule_names)
        self.assertTrue(
            any(item["url"] == "https://192.0.2.10/verify" for item in result["urls"])
        )

    def test_analysis_exposes_urls_found_in_plain_body(self):
        result = self.detector.analyze(
            {"email_body": "Please review https://example.com/class/notice."}
        )
        self.assertEqual(
            result["urls"],
            [
                {
                    "text": "https://example.com/class/notice",
                    "url": "https://example.com/class/notice",
                }
            ],
        )

    def test_normal_legitimate_looking_message_is_low_risk(self):
        result = self.detector.analyze(
            {
                "subject": "Study group meeting on Tuesday",
                "sender_display_name": "MCA Study Group",
                "sender_email": "study-group@example.com",
                "reply_to": "study-group@example.com",
                "email_body": "Hello, we will meet in the library at 3 p.m. No action is needed.",
            }
        )
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["verdict"], "Likely Legitimate")
        self.assertTrue(all(
            item["score_contribution"] == 0
            for item in result["rule_results"]
        ))

    def test_sensitive_keyword_without_a_request_is_not_enough(self):
        result = self.detector.analyze(
            {
                "subject": "Security reminder",
                "email_body": "Never share your password or OTP with anyone.",
            }
        )
        sensitive = next(
            item for item in result["rule_results"]
            if item["name"] == "sensitive_information_request"
        )
        self.assertEqual(sensitive["outcome"], "not_detected")

    def test_missing_sender_subject_reply_to_and_auth_are_safe(self):
        result = self.detector.analyze({"email_body": "Routine note."})
        rules = {item["name"]: item for item in result["rule_results"]}

        self.assertEqual(result["sender"]["email"], "")
        self.assertEqual(result["subject"], "")
        self.assertEqual(rules["sender_display_name_mismatch"]["outcome"], "unavailable")
        self.assertEqual(rules["reply_to_mismatch"]["outcome"], "unavailable")
        self.assertEqual(rules["email_authentication"]["outcome"], "unavailable")
        self.assertEqual(result["risk_score"], 0)
        self.assertTrue(result["limitations"])

    def test_repeated_indicators_are_not_counted_repeatedly(self):
        email = suspicious_email()
        email["email_body"] += (
            " Urgent today. Urgent today. "
            "Reply with your password and OTP again."
        )
        result = self.detector.analyze(email)
        by_name = {item["name"]: item for item in result["rule_results"]}

        self.assertEqual(
            by_name["urgency_or_threat"]["score_contribution"],
            self.detector.config.weights["urgency_or_threat"],
        )
        self.assertEqual(
            by_name["sensitive_information_request"]["score_contribution"],
            self.detector.config.weights["sensitive_information_request"],
        )
        self.assertLessEqual(result["risk_score"], 100)

    def test_custom_weights_and_thresholds_are_applied(self):
        config = DetectionConfig(
            weights={**DetectionConfig().weights, "reply_to_mismatch": 40},
            medium_threshold=10,
            high_threshold=35,
        )
        result = PhishingDetector(config).analyze(
            {
                "sender_email": "notice@example.com",
                "reply_to": "reply@example.net",
                "email_body": "Routine message.",
            }
        )
        self.assertEqual(result["risk_score"], 40)
        self.assertEqual(result["risk_level"], "High")

    def test_trusted_authentication_evidence_is_distinguished_from_untrusted(self):
        untrusted = self.detector.analyze(
            {
                "headers": {
                    "authentication_results": {
                        "trusted": False,
                        "values": ["spf=fail dkim=fail dmarc=fail"],
                    }
                }
            }
        )
        untrusted_rule = next(
            item for item in untrusted["rule_results"]
            if item["name"] == "email_authentication"
        )
        self.assertEqual(untrusted_rule["outcome"], "inconclusive")
        self.assertEqual(untrusted_rule["score_contribution"], 0)

        trusted = self.detector.analyze(
            {
                "headers": {
                    "authentication_results": {
                        "trusted": True,
                        "values": ["mx.example; spf=fail dkim=pass dmarc=fail"],
                    }
                }
            }
        )
        trusted_rule = next(
            item for item in trusted["rule_results"]
            if item["name"] == "email_authentication"
        )
        self.assertEqual(trusted_rule["outcome"], "detected")
        self.assertEqual(trusted_rule["authentication"]["spf"], "fail")
        self.assertEqual(trusted_rule["authentication"]["status"], "failed")

    def test_partial_authentication_pass_is_inconclusive_not_verified(self):
        result = self.detector.analyze(
            {
                "headers": {
                    "authentication_results": {
                        "trusted": True,
                        "values": ["mx.example; spf=pass"],
                    }
                }
            }
        )
        auth_result = next(
            item for item in result["rule_results"]
            if item["name"] == "email_authentication"
        )
        self.assertEqual(auth_result["outcome"], "inconclusive")
        self.assertEqual(auth_result["authentication"]["status"], "inconclusive")

    def test_structured_urls_detect_ip_shortener_and_mismatched_label(self):
        result = self.detector.analyze(
            {
                "subject": "Meeting information",
                "email_body": "Open the class note.",
                "urls": [
                    {"text": "https://campus.example.edu", "url": "http://192.0.2.20/login"},
                    {"text": "short link", "url": "https://bit.ly/abc"},
                ],
            }
        )
        url_rule = next(
            item for item in result["rule_results"]
            if item["name"] == "url_risk"
        )
        self.assertEqual(url_rule["outcome"], "detected")
        self.assertTrue(
            any("IP-address" in detail for detail in url_rule["details"])
        )
        self.assertTrue(
            any("shortening" in detail for detail in url_rule["details"])
        )
        self.assertTrue(
            any("Visible URL text differs" in detail for detail in url_rule["details"])
        )

    def test_strong_display_name_address_conflict_is_explained(self):
        result = self.detector.analyze(
            {
                "sender_display_name": "Campus Security Support",
                "sender_email": "notice@unrelated-mail.test",
                "subject": "Routine information",
                "email_body": "No link is included.",
            }
        )
        identity = next(
            item for item in result["rule_results"]
            if item["name"] == "sender_display_name_mismatch"
        )
        self.assertEqual(identity["outcome"], "detected")
        self.assertIn("display name", identity["explanation"])

    def test_example_domain_url_is_not_flagged_by_itself(self):
        result = self.detector.analyze(
            {
                "subject": "Class information",
                "email_body": "See https://example.com/class/notice",
            }
        )
        url_rule = next(
            item for item in result["rule_results"]
            if item["name"] == "url_risk"
        )
        self.assertEqual(url_rule["outcome"], "not_detected")
        self.assertEqual(result["risk_score"], 0)


class EmailParsingTests(unittest.TestCase):
    def test_raw_eml_parser_extracts_headers_plain_body_and_attachment_name(self):
        raw = (
            b"From: Course Office <office@example.com>\r\n"
            b"Reply-To: reply@example.net\r\n"
            b"Subject: Meeting notice\r\n"
            b"Content-Type: multipart/mixed; boundary=part\r\n\r\n"
            b"--part\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Hello, see https://example.com/class.\r\n"
            b"--part\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=notes.txt\r\n\r\n"
            b"not-read-as-code\r\n--part--\r\n"
        )
        parsed = parse_eml_bytes(raw)
        normalized = self.detector().analyze(parsed)

        self.assertEqual(parsed["sender_display_name"], "Course Office")
        self.assertEqual(parsed["sender_email"], "office@example.com")
        self.assertEqual(parsed["reply_to"], "reply@example.net")
        self.assertIn("Hello", parsed["email_body"])
        self.assertEqual(parsed["attachments"], [{"filename": "notes.txt"}])
        self.assertEqual(normalized["subject"], "Meeting notice")

    def test_local_eml_file_is_parsed_and_authentication_stays_untrusted(self):
        raw = (
            b"From: Security Desk <desk@example.test>\r\n"
            b"Subject: Local test\r\n"
            b"Authentication-Results: mx.example.test; spf=fail; dkim=fail; dmarc=fail\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Plain sample body."
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "sample.eml"
            path.write_bytes(raw)
            parsed = parse_eml_file(path)

        result = PhishingDetector().analyze(parsed)
        auth_result = next(
            item for item in result["rule_results"]
            if item["name"] == "email_authentication"
        )
        self.assertEqual(auth_result["outcome"], "inconclusive")
        self.assertIn("Plain sample body", parsed["email_body"])

    @staticmethod
    def detector():
        return PhishingDetector()

    def test_html_only_message_body_extracts_text_and_link_metadata(self):
        raw = (
            b"From: Library <library@example.com>\r\n"
            b"Subject: Hours\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body><p>Library is open.</p>"
            b'<a href="https://example.com/hours">Hours page</a></body></html>'
        )
        parsed = parse_eml_bytes(raw)
        self.assertIn("Library is open.", parsed["email_body"])
        self.assertEqual(
            parsed["urls"],
            [{"text": "Hours page", "url": "https://example.com/hours"}],
        )

    def test_structured_html_only_email_is_safely_flattened(self):
        normalized = normalize_email_input(
            {
                "subject": "Routine information",
                "html_body": (
                    '<p>Read the schedule</p><a href="https://example.com/schedule">'
                    "schedule</a><script>do not run</script>"
                ),
            }
        )
        result = PhishingDetector().analyze(normalized)
        self.assertIn("Read the schedule", normalized["email_body"])
        self.assertNotIn("do not run", normalized["email_body"])
        self.assertTrue(
            any(
                item["url"] == "https://example.com/schedule"
                for item in result["urls"]
            )
        )
        text, links = extract_html_content("<p>Hello <b>class</b></p>")
        self.assertEqual(text, "Hello class")
        self.assertEqual(links, [])

    def test_malformed_eml_and_bad_file_extension_fail_with_clear_errors(self):
        parsed = parse_raw_email("This is headerless plain email body.")
        self.assertEqual(parsed["subject"], "")
        self.assertIn("headerless", parsed["email_body"])

        with self.assertRaisesRegex(ValueError, "must have an .eml extension"):
            parse_eml_file("not-an-email.txt")

        with self.assertRaisesRegex(TypeError, "must be supplied as bytes"):
            parse_eml_bytes("not bytes")

    def test_oversized_raw_email_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exceeds"):
            parse_eml_bytes(b"x" * (5 * 1024 * 1024 + 1))


class DatasetEvaluationTests(unittest.TestCase):
    def test_existing_dataset_evaluation_has_both_classes_and_report(self):
        samples = load_labeled_dataset(DEFAULT_DATASET_PATH)
        result = evaluate_dataset(samples)
        report = format_evaluation_report(result)

        self.assertTrue(result["available"])
        self.assertEqual(result["sample_count"], 10)
        self.assertEqual(result["class_counts"], {"legitimate": 5, "phishing": 5})
        self.assertIn("Confusion matrix", report)
        self.assertIn("smoke test", report)

    def test_evaluator_reports_missing_class_limitation(self):
        result = evaluate_dataset(
            [{"email_id": "only-one", "email_type": "phishing"}]
        )
        self.assertFalse(result["available"])
        self.assertIn("both phishing and legitimate", result["limitation"])

    def test_evaluation_metrics_and_false_case_ids(self):
        class FixedDetector:
            def analyze(self, sample):
                predicted = {
                    "p-1": "phishing",
                    "p-2": "legitimate",
                    "l-1": "phishing",
                    "l-2": "legitimate",
                }[sample["email_id"]]
                return {
                    "predicted_class": predicted,
                    "risk_score": 50,
                    "verdict": "Suspicious",
                }

        samples = [
            {"email_id": "p-1", "email_type": "phishing"},
            {"email_id": "p-2", "email_type": "phishing"},
            {"email_id": "l-1", "email_type": "legitimate"},
            {"email_id": "l-2", "email_type": "legitimate"},
        ]
        result = evaluate_dataset(samples, detector=FixedDetector())

        self.assertEqual(result["confusion_matrix"]["true_positive"], 1)
        self.assertEqual(result["confusion_matrix"]["false_negative"], 1)
        self.assertEqual(result["confusion_matrix"]["false_positive"], 1)
        self.assertEqual(result["confusion_matrix"]["true_negative"], 1)
        self.assertEqual(result["accuracy"], 0.5)
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.5)
        self.assertEqual(result["f1_score"], 0.5)
        self.assertEqual(result["false_positives"], ["l-1"])
        self.assertEqual(result["false_negatives"], ["p-2"])


if __name__ == "__main__":
    unittest.main()
