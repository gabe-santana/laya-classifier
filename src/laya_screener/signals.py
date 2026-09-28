"""Deterministic evidence: facts about the message that code can check exactly.

A model reading the text cannot see that a DMARC check failed or that a link's
visible text points somewhere other than its href. These checks can, and they
never drift, so the policy treats them as evidence rather than as opinions.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

from .config import ScreenerConfig
from .parse import ParsedEmail

Severity = Literal["high", "medium", "low"]

# Characters attackers swap in to make a domain read like another one.
_CONFUSABLES = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "|": "l"})
_RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".bat", ".cmd", ".ps1", ".msi", ".jar", ".lnk", ".iso", ".img",
    ".html", ".htm", ".shtml", ".svg", ".docm", ".xlsm", ".pptm", ".one",
}
_DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".zip"}
_DOMAIN_IN_TEXT = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)


@dataclass
class Signal:
    id: str
    severity: Severity
    title: str
    detail: str


def _registrable(domain: str) -> str:
    """The last two labels, which is enough for the reserved .example domains the samples use."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def _levenshtein(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def lookalike_of(domain: str, known: list[str]) -> str | None:
    """The known domain this one imitates, or None. An exact match is not a lookalike."""
    candidate = _registrable(domain)
    if not candidate:
        return None
    for target in known:
        real = _registrable(target)
        if candidate == real or domain.lower().endswith("." + real):
            return None
    name = candidate.rsplit(".", 1)[0]
    for target in known:
        real_name = _registrable(target).rsplit(".", 1)[0]
        normalized = name.translate(_CONFUSABLES).replace("rn", "m").replace("vv", "w")
        if candidate.startswith("xn--"):
            return target
        if normalized == real_name or _levenshtein(name, real_name) <= 2:
            return target
        # northwind-payroll.example, secure-northwind.example
        if real_name in re.split(r"[-.]", normalized) or real_name in normalized.replace("-", ""):
            return target
    return None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def find_signals(mail: ParsedEmail, config: ScreenerConfig) -> list[Signal]:
    signals: list[Signal] = []
    sender_domain = mail.sender.domain
    known = config.known_domains

    failed = [m.upper() for m in ("dmarc", "spf", "dkim") if mail.auth.get(m) in ("fail", "softfail", "permerror")]
    if failed:
        severity: Severity = "high" if "DMARC" in failed else "medium"
        signals.append(Signal("auth_failed", severity, "Sender authentication failed",
                              f"{', '.join(failed)} did not pass for {sender_domain}."))

    imitated = lookalike_of(sender_domain, known)
    if imitated:
        signals.append(Signal("lookalike_sender", "high", "Lookalike sender domain",
                              f"{sender_domain} imitates {imitated}."))

    if mail.reply_to and mail.reply_to.domain and _registrable(mail.reply_to.domain) != _registrable(sender_domain):
        signals.append(Signal("reply_to_mismatch", "medium", "Replies go to a different domain",
                              f"From {sender_domain}, but Reply-To is {mail.reply_to.domain}."))

    display = mail.sender.name.lower()
    sender_is_ours = any(_registrable(sender_domain) == _registrable(d) for d in config.protected_domains)
    borrowed = [n for n in (*config.protected_names, *config.executive_names) if n.lower() in display]
    if borrowed and not sender_is_ours:
        signals.append(Signal("display_name_spoof", "medium", "Display name borrows an internal identity",
                              f'"{mail.sender.name}" is sent from the outside domain {sender_domain}.'))

    for link in mail.links:
        host = link.domain
        if not host:
            continue
        shown = _DOMAIN_IN_TEXT.search(link.text or "")
        if shown and link.text != link.href and _registrable(shown.group(1)) != _registrable(host):
            signals.append(Signal("link_text_mismatch", "high", "Link text hides its destination",
                                  f"Shows {shown.group(1).lower()} but opens {host}."))
            continue
        imitated = lookalike_of(host, known)
        if imitated:
            signals.append(Signal("lookalike_link", "high", "Link to a lookalike domain", f"{host} imitates {imitated}."))
        elif _is_ip(host):
            signals.append(Signal("ip_link", "medium", "Link to a bare IP address", f"Opens {host}."))
        elif _registrable(host) in config.shorteners or host in config.shorteners:
            signals.append(Signal("shortened_link", "low", "Shortened link", f"{host} hides the real destination."))

    for attachment in mail.attachments:
        name = attachment.filename.lower()
        suffixes = re.findall(r"\.[a-z0-9]{1,5}", name)
        last = suffixes[-1] if suffixes else ""
        if len(suffixes) >= 2 and suffixes[-2] in _DOCUMENT_EXTENSIONS and last in _RISKY_EXTENSIONS:
            signals.append(Signal("double_extension", "high", "Attachment disguised as a document",
                                  f"{attachment.filename} is really a {last} file."))
        elif last in _RISKY_EXTENSIONS:
            signals.append(Signal("risky_attachment", "high", "Attachment type that can run code",
                                  f"{attachment.filename} ({last}) can execute or open a fake login page."))

    # One finding per kind and detail is enough; a message with ten bad links is not ten times the evidence.
    unique: dict[tuple[str, str], Signal] = {}
    for signal in signals:
        unique.setdefault((signal.id, signal.detail), signal)
    return list(unique.values())


def trusted_origin(mail: ParsedEmail, config: ScreenerConfig) -> bool:
    """Authenticated mail from a known domain whose links all stay on known domains."""
    known = {_registrable(d) for d in config.known_domains}
    if _registrable(mail.sender.domain) not in known or mail.auth.get("dmarc") != "pass":
        return False
    if mail.reply_to and _registrable(mail.reply_to.domain) not in known:
        return False
    return all(_registrable(link.domain) in known for link in mail.links if link.domain)
