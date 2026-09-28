"""Combines Laya's reading of the text with the deterministic signals into a verdict.

Laya's answer is split into narrow questions because the broad one ("is this
phishing?") is the weakest on the English checkpoint zero-shot: on the sample
inbox it scored a CEO wire-fraud email at 3%. "Does it ask to move money or
for a sign-in?" combined with "does it push urgency or secrecy?" catches that
same email at 66%. Laya's risk is the higher of the two readings.

The signals are facts, so a high-severity one plus some suspicion from Laya is
enough to quarantine; Laya alone quarantines only when it is clearly confident.
The thresholds were chosen on the 18-email sample inbox: refit them on yours.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .signals import Signal

Verdict = Literal["deliver", "warn", "quarantine"]

SIGNAL_POINTS = {"high": 30, "medium": 15, "low": 8}
MAX_SIGNAL_POINTS = 60
LAYA_POINTS = 60
# Signals that are evidence on their own that the message is hostile, whatever the text says.
DECISIVE = {"double_extension", "risky_attachment", "link_text_mismatch"}


@dataclass
class Thresholds:
    laya_sure: float = 0.5  # Laya alone quarantines at or above this risk
    laya_suspicious: float = 0.3  # enough suspicion to act on a hard signal, or to warn
    trusted_discount: float = 0.5  # weight of Laya's risk on authenticated mail from known domains
    warn_risk: int = 30


@dataclass
class LayaView:
    """The parts of Laya's answers the policy uses, as plain numbers."""

    phishing: float
    phishing_confidence: float
    attack_type: str
    attack_confidence: float
    pressure: float  # expected level, 0 (none) to 2 (threats or secrecy)
    pressure_high: float  # probability of the top level: urgency, threats or secrecy
    asks_credentials: float
    asks_payment: float

    @property
    def social_engineering(self) -> float:
        return max(self.asks_credentials, self.asks_payment) * self.pressure_high

    @property
    def risk(self) -> float:
        return max(self.phishing, self.social_engineering)


@dataclass
class Decision:
    verdict: Verdict
    risk: int
    laya_risk: float
    reasons: list[str] = field(default_factory=list)


def decide(view: LayaView, signals: list[Signal], trusted_origin: bool = False,
           thresholds: Thresholds | None = None) -> Decision:
    t = thresholds or Thresholds()
    laya_risk = view.risk * (t.trusted_discount if trusted_origin else 1.0)
    signal_points = min(MAX_SIGNAL_POINTS, sum(SIGNAL_POINTS[s.severity] for s in signals))
    risk = round(min(100, LAYA_POINTS * laya_risk + signal_points))
    high = [s for s in signals if s.severity == "high"]

    reasons: list[str] = []
    if view.phishing >= 0.5:
        reasons.append(f"Laya reads it as phishing ({view.phishing:.0%}), most likely {view.attack_type.replace('_', ' ')}.")
    if view.social_engineering >= t.laya_suspicious:
        ask = "to move money" if view.asks_payment >= view.asks_credentials else "for a sign-in"
        reasons.append(f"It asks {ask} under pressure (social engineering {view.social_engineering:.0%}).")
    reasons.extend(f"{s.title}: {s.detail}" for s in signals)
    if trusted_origin and view.risk >= t.laya_suspicious:
        reasons.append("Authenticated mail from a known domain, with links only to known domains: Laya's reading counts half.")

    def result(verdict: Verdict) -> Decision:
        return Decision(verdict, risk, round(laya_risk, 3), reasons)

    if any(s.id in DECISIVE for s in high):
        return result("quarantine")
    if high and (laya_risk >= t.laya_suspicious or len(high) >= 2):
        return result("quarantine")
    if laya_risk >= t.laya_sure:
        return result("quarantine")
    if high or laya_risk >= t.laya_suspicious or risk >= t.warn_risk:
        return result("warn")
    if signals:
        return result("warn")
    return result("deliver") if reasons else Decision("deliver", risk, round(laya_risk, 3),
                                                      ["Nothing suspicious in the text or the headers."])
