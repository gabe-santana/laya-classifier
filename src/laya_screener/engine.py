"""The Laya side: one forward pass answers every question about an email."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

from .policy import LayaView
from .questions import QUESTIONS


@dataclass
class LayaResult:
    view: LayaView
    attack_probs: dict[str, float]
    pressure_probs: list[float]
    model: str
    routing_reason: str
    latency_ms: float


class Engine(Protocol):
    device: str

    @property
    def ready(self) -> bool: ...

    def predict(self, states: list[dict[str, str]]) -> list[LayaResult]: ...


def to_result(raw: dict[str, Any], latency_ms: float) -> LayaResult:
    """Reads Laya's answer dict (Router.predict output) into the numbers the policy uses."""
    a = raw["answers"]
    attack = a["attack_type"]
    pressure = a["pressure"]
    levels = sorted(pressure["probabilities"], key=int)
    view = LayaView(
        phishing=float(a["phishing"]["noul"]),
        phishing_confidence=float(a["phishing"]["answer_confidence"]),
        attack_type=attack["choice"],
        attack_confidence=float(attack["answer_confidence"]),
        pressure=float(pressure["score"]),
        pressure_high=float(pressure["probabilities"][levels[-1]]),
        asks_credentials=float(a["asks_credentials"]["noul"]),
        asks_payment=float(a["asks_payment"]["noul"]),
    )
    routing = raw.get("routing") or {}
    return LayaResult(
        view=view,
        attack_probs={k: float(v) for k, v in attack["probabilities"].items()},
        pressure_probs=[float(pressure["probabilities"][k]) for k in levels],
        model=routing.get("model", raw.get("model", "laya")),
        routing_reason=routing.get("reason", ""),
        latency_ms=latency_ms,
    )


class LayaEngine:
    """Laya's Router: English mail goes to `laya`, other languages to `laya-multilingual`.

    Checkpoints load in the background at startup, so the server answers
    /api/health right away and the dashboard can show when Laya is ready.
    """

    def __init__(self, device: str | None = None, preload: bool = True):
        import torch
        from laya import Router

        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self._router = Router(device=self.device, max_loaded=2)
        self._lock = threading.Lock()
        self._ready = threading.Event()
        if preload:
            threading.Thread(target=self._warm, daemon=True).start()
        else:
            self._ready.set()

    def _warm(self) -> None:
        # One English and one Portuguese pass load both checkpoints and compile the kernels.
        warmups = [
            {"subject": "Hello", "body": "Can we meet tomorrow to review the plan?"},
            {"subject": "Olá", "body": "Podemos conversar amanhã sobre o relatório de vendas?"},
        ]
        with self._lock:
            for state in warmups:
                self._router.predict(state, QUESTIONS)
        self._ready.set()

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    def predict(self, states: list[dict[str, str]]) -> list[LayaResult]:
        self._ready.wait()
        results = []
        # Torch forwards are not safe to interleave on one model, and a demo server is light
        # enough that serializing them costs nothing noticeable.
        with self._lock:
            for state in states:
                start = time.perf_counter()
                raw = self._router.predict(state, QUESTIONS)
                results.append(to_result(raw, (time.perf_counter() - start) * 1000))
        return results


class FakeEngine:
    """Deterministic stand-in for tests: keyword rules instead of a model."""

    device = "fake"
    ready = True

    def predict(self, states: list[dict[str, str]]) -> list[LayaResult]:
        out = []
        for state in states:
            text = " ".join(state.values()).lower()
            money = any(w in text for w in ("wire", "gift card", "bank", "transfer", "iban", "pagamento", "transferência"))
            login = any(w in text for w in ("sign in", "password", "verify", "confirme", "log in"))
            file = "attachment" in text or "anexo" in text
            phishing = 0.92 if (money or login) and any(w in text for w in ("urgent", "today", "24 hours", "hoje", "confidential")) else 0.08
            kind = "payment_fraud" if money else "credential_theft" if login else "malware" if file else "ordinary"
            probs = {k: (0.85 if k == kind else 0.05) for k in ("credential_theft", "payment_fraud", "malware", "ordinary")}
            urgent = 0.7 if phishing > 0.5 else 0.1
            view = LayaView(phishing, max(phishing, 1 - phishing), kind, 0.85, 1.8 if phishing > 0.5 else 0.3,
                            urgent, 0.9 if login else 0.1, 0.9 if money else 0.1)
            out.append(LayaResult(view, probs, [0.1, 0.2, 0.7] if phishing > 0.5 else [0.7, 0.2, 0.1],
                                  "fake", "keyword rules", 1.0))
        return out
