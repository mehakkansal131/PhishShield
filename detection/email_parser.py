"""Safe, local parsing helpers for structured emails and RFC 5322 messages."""

from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path


MAX_MESSAGE_BYTES = 5 * 1024 * 1024


class _HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_parts = []
        self.links = []
        self._active_anchor_text = []
        self._active_anchor_href = None
        self._ignored_tag = None

    def handle_starttag(self, tag, attrs):
        if self._ignored_tag:
            return
        if tag.lower() in {"script", "style"}:
            self._ignored_tag = tag.lower()
            return
        if tag.lower() != "a":
            return
        attributes = dict(attrs)
        self._active_anchor_href = attributes.get("href")
        self._active_anchor_text = []

    def handle_data(self, data):
        if self._ignored_tag:
            return
        text = data.strip()
        if not text:
            return
        self.text_parts.append(text)
        if self._active_anchor_href is not None:
            self._active_anchor_text.append(text)

    def handle_endtag(self, tag):
        if self._ignored_tag:
            if tag.lower() == self._ignored_tag:
                self._ignored_tag = None
            return
        if tag.lower() == "a" and self._active_anchor_href is not None:
            link_text = " ".join(self._active_anchor_text).strip()
            self.links.append(
                {"text": link_text, "url": self._active_anchor_href}
            )
            self._active_anchor_href = None
            self._active_anchor_text = []


def extract_html_content(html):
    """Return display text and anchor metadata without executing HTML."""
    parser = _HTMLTextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except (ValueError, AssertionError):
        return " ".join(html.split()), []
    return " ".join(parser.text_parts), parser.links


def parse_eml_bytes(raw_message):
    """Parse bounded RFC email bytes into normalized fields and metadata."""
    if not isinstance(raw_message, bytes):
        raise TypeError("An .eml message must be supplied as bytes.")
    if len(raw_message) > MAX_MESSAGE_BYTES:
        raise ValueError(f"Email message exceeds the {MAX_MESSAGE_BYTES}-byte limit.")

    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    if not isinstance(message, Message):
        raise ValueError("The supplied content could not be parsed as an email.")

    plain_bodies = []
    html_bodies = []
    attachments = []

    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append({"filename": filename})
            continue

        content_type = part.get_content_type().lower()
        disposition = part.get_content_disposition()
        if disposition == "attachment":
            continue
        try:
            payload = part.get_content()
        except (LookupError, UnicodeError, AttributeError):
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                charset = part.get_content_charset() or "utf-8"
                payload = payload.decode(charset, errors="replace")
            elif not isinstance(payload, str):
                payload = ""
        if not isinstance(payload, str):
            continue
        if content_type == "text/plain":
            plain_bodies.append(payload)
        elif content_type == "text/html":
            html_bodies.append(payload)

    links = []
    if plain_bodies:
        body = "\n".join(plain_bodies)
    elif html_bodies:
        extracted = [extract_html_content(value) for value in html_bodies]
        body = "\n".join(text for text, _links in extracted)
        for _text, found_links in extracted:
            links.extend(found_links)
    else:
        body = ""

    auth_headers = message.get_all("Authentication-Results", [])
    trusted_authentication_results = None
    if auth_headers:
        trusted_authentication_results = {
            "trusted": False,
            "values": [str(value) for value in auth_headers],
            "source": "message headers; receiver trust not established",
        }

    return {
        "subject": _header_text(message.get("Subject")),
        "sender_display_name": _display_name_from_header(message.get("From")),
        "sender_email": _address_from_header(message.get("From")),
        "reply_to": _address_from_header(message.get("Reply-To")),
        "email_body": body,
        "urls": links,
        "attachments": attachments,
        "headers": {
            "authentication_results": trusted_authentication_results,
        },
        "source": "eml",
    }


def parse_eml_file(path):
    """Read and parse a local .eml path without contacting external systems."""
    source_path = Path(path)
    if source_path.suffix.lower() != ".eml":
        raise ValueError("Input file must have an .eml extension.")
    try:
        with source_path.open("rb") as message_file:
            raw_message = message_file.read(MAX_MESSAGE_BYTES + 1)
    except OSError as error:
        raise ValueError(f"Could not read the .eml file: {error}") from error
    return parse_eml_bytes(raw_message)


def parse_raw_email(raw_text):
    """Parse raw RFC email text; treat headerless text as a plain body."""
    if not isinstance(raw_text, str):
        raise TypeError("Raw email input must be text.")
    encoded = raw_text.encode("utf-8", errors="replace")
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ValueError(f"Email message exceeds the {MAX_MESSAGE_BYTES}-byte limit.")
    return parse_eml_bytes(encoded)


def normalize_email_input(email):
    """Normalize dataset/structured records and safely flatten HTML bodies."""
    if not isinstance(email, dict):
        raise TypeError("Structured email input must be a dictionary.")

    normalized = dict(email)
    body = email.get("email_body", email.get("body", ""))
    if body is None:
        body = ""
    if not isinstance(body, str):
        raise TypeError("Email body must be text.")

    html_body = email.get("html_body")
    html_links = []
    if isinstance(html_body, str) and html_body:
        html_text, html_links = extract_html_content(html_body)
        if not body:
            body = html_text
        else:
            body = f"{body}\n{html_text}"

    normalized["email_body"] = body
    normalized["subject"] = _as_text(email.get("subject"))
    normalized["sender_display_name"] = _as_text(
        email.get("sender_display_name", email.get("from_name", ""))
    )
    normalized["sender_email"] = _as_text(
        email.get("sender_email", email.get("from", ""))
    )
    normalized["reply_to"] = _as_text(email.get("reply_to"))

    urls = email.get("urls", [])
    if urls is None:
        urls = []
    if not isinstance(urls, list):
        raise TypeError("The optional 'urls' field must be a list.")
    normalized["urls"] = list(urls) + html_links
    normalized.pop("html_body", None)

    attachments = email.get("attachments", [])
    if attachments is None:
        attachments = []
    if not isinstance(attachments, list):
        raise TypeError("The optional 'attachments' field must be a list.")
    normalized["attachments"] = attachments
    return normalized


def _header_text(value):
    return str(value).strip() if value is not None else ""


def _address_from_header(value):
    if value is None:
        return ""
    addresses = getattr(value, "addresses", ())
    if addresses:
        return str(addresses[0].addr_spec).strip()
    _name, address = parseaddr(str(value))
    return address.strip() if address else str(value).strip()


def _display_name_from_header(value):
    if value is None:
        return ""
    display_name = getattr(value, "display_name", None)
    if display_name:
        return str(display_name).strip()
    name, _address = parseaddr(str(value))
    return name.strip() if name else str(value).strip()


def _as_text(value):
    if value is None:
        return ""
    return value.strip() if isinstance(value, str) else str(value).strip()
