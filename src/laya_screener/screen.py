"""parse -> (signals, Laya) -> policy: the whole screening pipeline for one or many emails."""

from __future__ import annotations

import time
from dataclasses import asdict
from typing import Any

from .config import ScreenerConfig, load_config
from .engine import Engine
from .parse import ParsedEmail, parse_email
from .policy import Thresholds, decide
from .questions import email_state
from .signals import find_signals, trusted_origin


class Screener:
    def __init__(self, engine: Engine, config: ScreenerConfig | None = None, thresholds: Thresholds | None = None):
        self.engine = engine
        self.config = config or load_config()
        self.thresholds = thresholds or Thresholds()

    def screen(self, raw: bytes | str) -> dict[str, Any]:
        return self.screen_many([raw])[0]

    def screen_many(self, raws: list[bytes | str]) -> list[dict[str, Any]]:
        start = time.perf_counter()
        mails = [parse_email(raw) for raw in raws]
        laya = self.engine.predict([email_state(m) for m in mails])
        results = []
        for mail, reading in zip(mails, laya):
            signals = find_signals(mail, self.config)
            trusted = trusted_origin(mail, self.config)
            decision = decide(reading.view, signals, trusted, self.thresholds)
            results.append({
                "verdict": decision.verdict,
                "risk": decision.risk,
                "trusted_origin": trusted,
                "reasons": decision.reasons,
                "signals": [asdict(s) for s in signals],
                "laya": {
                    **asdict(reading.view),
                    "social_engineering": round(reading.view.social_engineering, 4),
                    "risk": decision.laya_risk,
                    "attack_probs": reading.attack_probs,
                    "pressure_probs": reading.pressure_probs,
                    "model": reading.model,
                    "routing_reason": reading.routing_reason,
                    "latency_ms": round(reading.latency_ms, 1),
                },
                "email": _email_json(mail),
            })
        elapsed = (time.perf_counter() - start) * 1000 / max(1, len(results))
        for result in results:
            result["elapsed_ms"] = round(elapsed, 1)
        return results


def _email_json(mail: ParsedEmail) -> dict[str, Any]:
    return {
        "from": asdict(mail.sender),
        "reply_to": asdict(mail.reply_to) if mail.reply_to else None,
        "subject": mail.subject,
        "date": mail.date,
        "auth": mail.auth,
        "links": [{"text": l.text, "href": l.href, "domain": l.domain} for l in mail.links],
        "attachments": [asdict(a) for a in mail.attachments],
        "body_preview": mail.body[:1200],
    }


def compose_email(sender: str, subject: str, body: str) -> str:
    """A minimal RFC 5322 message for text typed into the dashboard or posted without headers."""
    from email.message import EmailMessage

    message = EmailMessage()
    message["From"] = sender or "unknown@unknown.invalid"
    message["To"] = "you@unknown.invalid"
    message["Subject"] = subject or ""
    message.set_content(body or "")
    return message.as_string()
