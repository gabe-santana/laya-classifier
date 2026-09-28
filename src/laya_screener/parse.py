"""Turn a raw RFC 5322 message into the fields the screener reasons about."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


@dataclass
class Address:
    name: str
    address: str

    @property
    def domain(self) -> str:
        return self.address.rpartition("@")[2].lower()


@dataclass
class Link:
    href: str
    text: str

    @property
    def domain(self) -> str:
        return (urlsplit(self.href).hostname or "").lower()


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int


@dataclass
class ParsedEmail:
    sender: Address
    reply_to: Address | None
    to: list[Address]
    subject: str
    body: str
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    # spf / dkim / dmarc -> "pass", "fail", "softfail", "none"...; absent when the header is missing.
    auth: dict[str, str] = field(default_factory=dict)
    date: str = ""


class _HtmlText(HTMLParser):
    """Collects visible text and every <a href> with its anchor text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[Link] = []
        self._href: str | None = None
        self._anchor: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or None
            self._anchor = []
        elif tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append(Link(self._href, " ".join("".join(self._anchor).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        if self._href is not None:
            self._anchor.append(data)

    def text(self) -> str:
        lines = (" ".join(line.split()) for line in "".join(self.parts).splitlines())
        return "\n".join(line for line in lines if line)


def _address(value: str | None) -> Address | None:
    if not value:
        return None
    name, addr = parseaddr(str(value))
    return Address(name.strip(), addr.strip().lower()) if addr else None


def _auth_results(message: EmailMessage) -> dict[str, str]:
    results: dict[str, str] = {}
    for header in message.get_all("Authentication-Results", []):
        for method in ("spf", "dkim", "dmarc"):
            match = re.search(rf"\b{method}=(\w+)", str(header), re.I)
            if match and method not in results:
                results[method] = match.group(1).lower()
    return results


def parse_email(raw: bytes | str) -> ParsedEmail:
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    message = message_from_bytes(data, policy=policy.default)
    assert isinstance(message, EmailMessage)

    plain: list[str] = []
    html_text = _HtmlText()
    attachments: list[Attachment] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append(Attachment(filename or "unnamed", part.get_content_type(), len(payload)))
            continue
        if part.get_content_type() == "text/plain":
            plain.append(part.get_content())
        elif part.get_content_type() == "text/html":
            html_text.feed(part.get_content())

    body = "\n".join(p.strip() for p in plain if p.strip()) or html_text.text()
    links = list(html_text.links)
    seen = {link.href for link in links}
    for url in URL_RE.findall(body):
        url = url.rstrip(".,;:!?")
        if url not in seen:
            links.append(Link(url, url))
            seen.add(url)

    sender = _address(message.get("From")) or Address("", "")
    return ParsedEmail(
        sender=sender,
        reply_to=_address(message.get("Reply-To")),
        to=[Address(n, a.lower()) for n, a in getaddresses([str(v) for v in message.get_all("To", [])]) if a],
        subject=str(message.get("Subject", "")).strip(),
        body=body.strip(),
        links=links,
        attachments=attachments,
        auth=_auth_results(message),
        date=str(message.get("Date", "")),
    )
