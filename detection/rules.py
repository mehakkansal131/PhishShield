"""Explainable indicators used by the local phishing risk scorer."""

import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import unquote, urlsplit


URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>'\"()\]]+")
URGENT_PATTERNS = (
    r"\bwithin\s+\d+\s+(?:minutes?|hours?|days?)\b",
    r"\b(?:immediately|urgent|act now|final warning|expires today)\b",
    r"\b(?:account|access|service)\s+(?:will be|has been)\s+(?:suspended|disabled|closed)\b",
    r"\b(?:legal action|penalty|terminate your account)\b",
)
SENSITIVE_PATTERNS = (
    r"\b(?:send|share|reply with|provide|confirm|verify|enter|submit|type|give)\b"
    r".{0,50}\b(?:password|passcode|one[- ]time password|otp|verification code|"
    r"bank account|credit card|debit card|cvv|card number|bank details)\b",
    r"\b(?:password|passcode|one[- ]time password|otp|verification code|"
    r"bank account|credit card|debit card|cvv|card number|bank details)\b"
    r".{0,30}\b(?:in reply|to us|to claim|to restore|to verify|to confirm)\b",
)
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
}
RESERVED_EDUCATIONAL_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
}
SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd",
    ".ps1", ".hta", ".iso", ".img", ".lnk", ".jar", ".msi",
}
AUTH_STATES = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}


def sender_identity_rule(email):
    display = email["sender_display_name"].strip()
    address = email["sender_email"].strip()
    if not display or not address:
        return _result(
            "sender_display_name_mismatch",
            "unavailable",
            0,
            "A sender display name or sender address is missing.",
        )

    _parsed_name, parsed_address = parseaddr(address)
    if parsed_address:
        address = parsed_address
    _, domain = _split_email(address)
    display_clean = re.sub(r"<[^>]*>", "", display).strip()
    if "@" not in address or not domain:
        return _result(
            "sender_display_name_mismatch",
            "inconclusive",
            0,
            "The sender address could not be reliably parsed for comparison.",
        )

    # A display name is a free-form label; only flag strong conflicts with
    # explicit organization/domain-like wording, not ordinary name differences.
    brand_tokens = {
        token.lower()
        for token in re.findall(r"[A-Za-z0-9]+", display_clean)
        if len(token) >= 4
    }
    domain_tokens = {
        token.lower()
        for token in re.findall(r"[A-Za-z0-9]+", domain)
        if len(token) >= 4
    }
    local_tokens = {
        token.lower()
        for token in re.findall(r"[A-Za-z0-9]+", address.split("@", 1)[0])
        if len(token) >= 4
    }
    trustworthy_tokens = domain_tokens | local_tokens
    if (
        brand_tokens
        and trustworthy_tokens
        and not brand_tokens.intersection(trustworthy_tokens)
        and any(
            word in display_clean.lower()
            for word in (
                "support", "security", "bank", "admin", "office", "desk",
                "operations", "people", "hr", "campus", "team",
            )
        )
    ):
        return _result(
            "sender_display_name_mismatch",
            "detected",
            None,
            "The sender uses an organization/authority-style display name that does not resemble the sender address.",
        )
    return _result(
        "sender_display_name_mismatch",
        "not_detected",
        0,
        "No strong display-name and sender-address conflict was identified.",
    )


def reply_to_rule(email):
    sender = _normalized_address(email["sender_email"])
    reply_to = _normalized_address(email["reply_to"])
    if not reply_to:
        return _result(
            "reply_to_mismatch",
            "unavailable",
            0,
            "No Reply-To address was supplied.",
        )
    if not sender:
        return _result(
            "reply_to_mismatch",
            "inconclusive",
            0,
            "The sender address is unavailable, so Reply-To could not be compared.",
        )
    if reply_to != sender:
        return _result(
            "reply_to_mismatch",
            "detected",
            None,
            "The Reply-To address differs from the sender address; this can be legitimate but merits verification.",
        )
    return _result(
        "reply_to_mismatch",
        "not_detected",
        0,
        "The supplied Reply-To address matches the sender address.",
    )


def url_rule(email):
    urls = _collect_urls(email)
    if not urls:
        return _result(
            "url_risk",
            "not_detected",
            0,
            "No URLs were found in the supplied subject, body, or URL metadata.",
            urls=[],
        )

    findings = []
    seen = set()
    for item in urls:
        url = item["url"].strip(".,;:!?")
        key = url.casefold()
        if key in seen:
            continue
        seen.add(key)
        assessment = _assess_url(url, item.get("text", ""))
        if assessment:
            findings.extend(assessment)

    unique_urls = []
    seen_urls = set()
    for item in urls:
        key = item["url"].strip(".,;:!?").casefold()
        if key not in seen_urls:
            seen_urls.add(key)
            unique_urls.append(
                {"text": item.get("text", ""), "url": item["url"].strip(".,;:!?")}
            )

    if findings:
        unique_findings = list(dict.fromkeys(findings))
        return _result(
            "url_risk",
            "detected",
            None,
            "One or more URL patterns warrant caution; destinations were analyzed as text only and were not contacted.",
            urls=unique_urls,
            details=unique_findings,
        )
    return _result(
        "url_risk",
        "not_detected",
        0,
        "No configured high-risk URL pattern was detected. This does not prove that a URL is safe.",
        urls=unique_urls,
    )


def urgency_rule(email):
    text = f'{email["subject"]}\n{email["email_body"]}'
    matches = _matching_patterns(URGENT_PATTERNS, text)
    if matches:
        return _result(
            "urgency_or_threat",
            "detected",
            None,
            "The message contains time pressure or threatening account language.",
            details=matches,
        )
    return _result(
        "urgency_or_threat",
        "not_detected",
        0,
        "No configured urgency or threat phrase was found.",
    )


def sensitive_request_rule(email):
    text = f'{email["subject"]}\n{email["email_body"]}'
    matches = []
    for pattern in SENSITIVE_PATTERNS:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            context = text[max(0, match.start() - 35):match.end() + 10]
            if re.search(
                r"\b(?:never|do not|don't|should not|must not)\s+"
                r"(?:send|share|reply with|provide|confirm|verify|enter|submit|type|give)\b",
                context,
                flags=re.IGNORECASE,
            ):
                continue
            matches.append(match.group(0).strip())
    matches = list(dict.fromkeys(matches))
    if matches:
        return _result(
            "sensitive_information_request",
            "detected",
            None,
            "The message appears to mention credentials, verification codes, or payment details in a request-like context.",
            details=matches,
        )
    return _result(
        "sensitive_information_request",
        "not_detected",
        0,
        "No configured sensitive-information request pattern was found.",
    )


def linked_action_context_rule(email):
    """Flag links combined with a context-specific request, not a link alone."""
    urls = _collect_urls(email)
    if not urls:
        return _result(
            "linked_action_context",
            "not_detected",
            0,
            "No link-plus-request combination was present.",
        )
    text = f'{email["subject"]}\n{email["email_body"]}'.lower()
    action_words = (
        "visit", "view", "viewed", "viewing", "review", "reviewed",
        "confirm", "click", "open", "check", "update", "claim", "verify",
    )
    context_words = (
        "account", "security", "policy", "parcel", "delivery", "reward",
        "certificate", "notes", "document", "payment", "message",
    )
    found_actions = [word for word in action_words if re.search(rf"\b{word}\b", text)]
    found_contexts = [word for word in context_words if re.search(rf"\b{word}\b", text)]
    if found_actions and found_contexts:
        return _result(
            "linked_action_context",
            "detected",
            None,
            "A link appears alongside an action request and account, service, reward, or document context. This combination deserves verification; it is not proof of phishing.",
            details=[
                f"Action language: {', '.join(found_actions)}",
                f"Context terms: {', '.join(found_contexts)}",
            ],
        )
    return _result(
        "linked_action_context",
        "not_detected",
        0,
        "No context-specific request was found alongside the supplied link(s).",
    )


def attachment_rule(email):
    attachments = email["attachments"]
    suspicious = []
    for item in attachments:
        if isinstance(item, str):
            filename = item
        elif isinstance(item, dict):
            filename = item.get("filename", "")
        else:
            continue
        if not isinstance(filename, str) or not filename:
            continue
        extension = _filename_extension(filename)
        if extension in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            suspicious.append(filename)
    if suspicious:
        return _result(
            "attachment_metadata",
            "detected",
            None,
            "Attachment metadata contains a file extension commonly associated with executable or script content; no file was opened.",
            details=list(dict.fromkeys(suspicious)),
        )
    if not attachments:
        return _result(
            "attachment_metadata",
            "not_detected",
            0,
            "No attachment metadata was supplied.",
        )
    return _result(
        "attachment_metadata",
        "not_detected",
        0,
        "No configured high-risk attachment extension was identified; file safety was not verified.",
    )


def authentication_rule(email):
    headers = email.get("headers")
    auth = headers.get("authentication_results") if isinstance(headers, dict) else None
    if auth is None:
        return _result(
            "email_authentication",
            "unavailable",
            0,
            "No authentication-results evidence was supplied; missing headers are not evidence of phishing.",
            authentication={
                "status": "unavailable",
                "spf": "unavailable",
                "dkim": "unavailable",
                "dmarc": "unavailable",
            },
        )

    if not isinstance(auth, dict):
        return _result(
            "email_authentication",
            "inconclusive",
            0,
            "Authentication evidence was not supplied in a recognized structure.",
            authentication={
                "status": "inconclusive",
                "spf": "inconclusive",
                "dkim": "inconclusive",
                "dmarc": "inconclusive",
            },
        )

    if not auth.get("trusted", False):
        return _result(
            "email_authentication",
            "inconclusive",
            0,
            "Authentication-Results data is present, but its receiving-server trust was not established.",
            authentication={
                "status": "inconclusive",
                "spf": "inconclusive",
                "dkim": "inconclusive",
                "dmarc": "inconclusive",
            },
        )

    text_parts = []
    for value in auth.get("values", []):
        if isinstance(value, str):
            text_parts.append(value)
    fields = auth.get("results", {})
    if isinstance(fields, dict):
        text_parts.extend(f"{key}={value}" for key, value in fields.items())
    combined = " ".join(text_parts).lower()
    statuses = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        matches = re.findall(
            rf"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            combined,
        )
        statuses[mechanism] = matches[0] if matches else "unavailable"
    failures = [
        mechanism
        for mechanism, status in statuses.items()
        if status in {"fail", "softfail", "permerror"}
    ]
    if failures:
        return _result(
            "email_authentication",
            "detected",
            None,
            "Trusted receiver-provided authentication results include a failure. Authentication failure is a signal, not proof of malicious content.",
            authentication={"status": "failed", **statuses},
            details=failures,
        )
    if all(status == "pass" for status in statuses.values()):
        return _result(
            "email_authentication",
            "not_detected",
            0,
            "Trusted receiver results show SPF, DKIM, and DMARC passing; this does not prove the message is benign.",
            authentication={"status": "verified", **statuses},
        )
    return _result(
        "email_authentication",
        "inconclusive",
        0,
        "Trusted authentication evidence is present but does not support a pass/fail conclusion.",
        authentication={"status": "inconclusive", **statuses},
    )


def run_detection_rules(email):
    """Run each independent detector rule and return rule-level evidence."""
    return [
        sender_identity_rule(email),
        reply_to_rule(email),
        url_rule(email),
        urgency_rule(email),
        sensitive_request_rule(email),
        linked_action_context_rule(email),
        attachment_rule(email),
        authentication_rule(email),
    ]


def _result(name, outcome, contribution, explanation, **extra):
    result = {
        "name": name,
        "outcome": outcome,
        "explanation": explanation,
        "score_contribution": contribution,
    }
    result.update(extra)
    return result


def _normalized_address(value):
    if not isinstance(value, str) or not value.strip():
        return ""
    _name, address = parseaddr(value.strip())
    return (address or value).strip().casefold()


def _split_email(value):
    address = _normalized_address(value)
    if "@" not in address:
        return "", ""
    local, domain = address.rsplit("@", 1)
    return local, domain.rstrip(".")


def _matching_patterns(patterns, text):
    return list(
        dict.fromkeys(
            match.group(0).strip()
            for pattern in patterns
            for match in re.finditer(pattern, text, flags=re.IGNORECASE)
        )
    )


def _collect_urls(email):
    candidates = []
    subject = email["subject"]
    body = email["email_body"]
    combined = f"{subject}\n{body}"
    candidates.extend(
        {
            "text": match.group(0).strip(".,;:!?"),
            "url": match.group(0).strip(".,;:!?"),
        }
        for match in URL_PATTERN.finditer(combined)
    )
    for item in email["urls"]:
        if isinstance(item, str):
            candidates.append({"text": "", "url": item})
        elif isinstance(item, dict):
            destination = item.get("url", item.get("href", ""))
            visible = item.get("text", item.get("label", ""))
            if isinstance(destination, str) and destination.strip():
                candidates.append({"text": str(visible), "url": destination})
    return candidates


def _assess_url(value, visible_text):
    normalized = value.strip()
    if normalized.lower().startswith("www."):
        normalized = "http://" + normalized
    try:
        parsed = urlsplit(normalized)
        hostname = (parsed.hostname or "").rstrip(".").lower()
    except ValueError:
        return ["URL could not be parsed cleanly."]
    if not hostname:
        return ["URL has no recognizable hostname."]

    findings = []
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        findings.append("URL uses an IP-address host rather than a domain name.")
    except ValueError:
        pass

    if hostname in SHORTENER_DOMAINS:
        findings.append("URL uses a known URL-shortening domain.")
    try:
        if hostname.startswith("xn--") or ".xn--" in hostname:
            findings.append("URL contains an internationalized punycode hostname.")
    except AttributeError:
        pass

    if parsed.username is not None or parsed.password is not None:
        findings.append("URL includes user-information before the host, which can obscure its destination.")

    visible_urls = URL_PATTERN.findall(visible_text or "")
    for visible_url in visible_urls:
        visible_host = _url_hostname(visible_url)
        if visible_host and visible_host != hostname:
            findings.append("Visible URL text differs from the link destination.")
            break
    if visible_text and re.fullmatch(r"(?i)(?:https?://)?[a-z0-9.-]+\.[a-z]{2,}", visible_text.strip()):
        visible_host = _url_hostname(visible_text.strip())
        if visible_host and visible_host != hostname:
            findings.append("Visible URL text differs from the link destination.")

    if hostname not in RESERVED_EDUCATIONAL_DOMAINS:
        labels = hostname.split(".")
        if len(labels) >= 5:
            findings.append("URL uses a deeply nested hostname that may be difficult to interpret.")
        if any(len(label) >= 28 for label in labels):
            findings.append("URL contains an unusually long hostname label.")
    return findings


def _url_hostname(value):
    normalized = value.strip()
    if normalized.lower().startswith("www."):
        normalized = "http://" + normalized
    elif not re.match(r"(?i)^https?://", normalized):
        normalized = "http://" + normalized
    try:
        return (urlsplit(normalized).hostname or "").rstrip(".").lower()
    except ValueError:
        return ""


def _filename_extension(filename):
    name = unquote(filename).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]
