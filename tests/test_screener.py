"""Tests that run without downloading a checkpoint: the parser, the signals, the policy and the API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from laya_screener.api import create_app
from laya_screener.config import ScreenerConfig, load_config
from laya_screener.engine import FakeEngine, to_result
from laya_screener.parse import parse_email
from laya_screener.policy import LayaView, decide
from laya_screener.screen import Screener, compose_email
from laya_screener.signals import Signal, find_signals, lookalike_of, trusted_origin

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
LABELS = json.loads((SAMPLES / "labels.json").read_text(encoding="utf-8"))
CONFIG = load_config()


def sample(name: str):
    return parse_email((SAMPLES / name).read_bytes())


def ids(signals: list[Signal]) -> set[str]:
    return {s.id for s in signals}


def view(**overrides) -> LayaView:
    base = dict(phishing=0.02, phishing_confidence=0.98, attack_type="ordinary", attack_confidence=0.9,
                pressure=0.4, pressure_high=0.05, asks_credentials=0.1, asks_payment=0.1)
    return LayaView(**{**base, **overrides})


class TestParse:
    def test_reads_headers_body_and_auth(self):
        mail = sample("mailbox-full-lookalike.eml")
        assert mail.sender.address == "it-support@n0rthwind.example"
        assert mail.sender.domain == "n0rthwind.example"
        assert mail.auth == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
        assert "98%" in mail.body

    def test_keeps_html_anchor_text_apart_from_href(self):
        link = next(l for l in sample("mailbox-full-lookalike.eml").links if "login" in l.href)
        assert link.text == "https://portal.northwind.example"
        assert link.domain == "n0rthwind-login.example"

    def test_lists_attachments(self):
        [attachment] = sample("scanned-document-exe.eml").attachments
        assert attachment.filename == "Scan_0928.pdf.exe"

    def test_composes_a_message_from_plain_fields(self):
        mail = parse_email(compose_email("Eve <eve@evil.example>", "Hi", "Click https://evil.example/x"))
        assert mail.sender.domain == "evil.example"
        assert [l.domain for l in mail.links] == ["evil.example"]


class TestSignals:
    @pytest.mark.parametrize("domain", ["n0rthwind.example", "northwind-payroll.example", "nortwind.example",
                                        "xn--northwnd-2za.example", "fabrikam-billing.example"])
    def test_spots_lookalike_domains(self, domain):
        assert lookalike_of(domain, ["northwind.example", "fabrikam.example"])

    @pytest.mark.parametrize("domain", ["northwind.example", "mail.northwind.example", "cloudweekly.example"])
    def test_leaves_real_and_unrelated_domains_alone(self, domain):
        assert lookalike_of(domain, ["northwind.example", "fabrikam.example"]) is None

    def test_catches_the_hard_evidence_in_the_samples(self):
        assert {"auth_failed", "lookalike_sender", "link_text_mismatch"} <= ids(find_signals(sample("mailbox-full-lookalike.eml"), CONFIG))
        assert "double_extension" in ids(find_signals(sample("scanned-document-exe.eml"), CONFIG))
        assert "risky_attachment" in ids(find_signals(sample("boleto-atualizado-html.eml"), CONFIG))
        assert "lookalike_sender" in ids(find_signals(sample("vendor-bank-change.eml"), CONFIG))
        assert "reply_to_mismatch" in ids(find_signals(sample("lista-parceiros-reply-to.eml"), CONFIG))
        assert "display_name_spoof" in ids(find_signals(sample("ceo-wire-transfer.eml"), CONFIG))

    @pytest.mark.parametrize("label", [l for l in LABELS if l["verdict"] == "deliver"], ids=lambda l: l["file"])
    def test_finds_nothing_in_clean_legitimate_mail(self, label):
        assert find_signals(sample(label["file"]), CONFIG) == []

    def test_trusts_only_authenticated_mail_that_stays_on_known_domains(self):
        assert trusted_origin(sample("password-reset-requested.eml"), CONFIG)
        assert not trusted_origin(sample("mailbox-full-lookalike.eml"), CONFIG)
        assert not trusted_origin(sample("newsletter-cloud-weekly.eml"), CONFIG)


class TestPolicy:
    def test_delivers_clean_mail(self):
        assert decide(view(), []).verdict == "deliver"

    def test_a_decisive_signal_quarantines_whatever_laya_says(self):
        signal = Signal("double_extension", "high", "t", "d")
        assert decide(view(), [signal]).verdict == "quarantine"

    def test_a_hard_signal_needs_some_suspicion_from_laya(self):
        signal = Signal("lookalike_sender", "high", "t", "d")
        assert decide(view(), [signal]).verdict == "warn"
        assert decide(view(asks_payment=0.8, pressure_high=0.6), [signal]).verdict == "quarantine"

    def test_social_engineering_catches_what_the_broad_question_misses(self):
        # The CEO wire-fraud sample: 3% phishing on the broad question, but it asks for money under pressure.
        ceo = view(phishing=0.03, asks_payment=0.89, pressure_high=0.74)
        assert ceo.risk == pytest.approx(0.89 * 0.74)
        assert decide(ceo, []).verdict == "quarantine"

    def test_trusted_origin_halves_layas_weight(self):
        reset = view(phishing=0.39, asks_credentials=0.86, pressure_high=0.47)
        assert decide(reset, []).verdict == "warn"
        assert decide(reset, [], trusted_origin=True).verdict == "deliver"

    def test_any_signal_at_least_warns(self):
        assert decide(view(), [Signal("reply_to_mismatch", "medium", "t", "d")]).verdict == "warn"


def test_reads_layas_answer_format():
    raw = {
        "answers": {
            "phishing": {"type": "noul", "noul": 0.87, "answer_confidence": 0.87},
            "attack_type": {"type": "choice", "choice": "credential_theft", "answer_confidence": 0.49,
                            "probabilities": {"credential_theft": 0.49, "payment_fraud": 0.08, "malware": 0.38, "ordinary": 0.05}},
            "pressure": {"type": "score", "score": 1.72, "probabilities": {"0": 0.02, "1": 0.24, "2": 0.74}},
            "asks_credentials": {"type": "noul", "noul": 0.9},
            "asks_payment": {"type": "noul", "noul": 0.28},
        },
        "routing": {"model": "english", "reason": "English Latin text"},
    }
    result = to_result(raw, 61.0)
    assert result.view.pressure_high == 0.74
    assert result.pressure_probs == [0.02, 0.24, 0.74]
    assert result.model == "english"


class TestApi:
    @pytest.fixture
    def client(self):
        return TestClient(create_app(Screener(FakeEngine(), CONFIG)))

    def test_health(self, client):
        assert client.get("/api/health").json()["ready"] is True

    def test_serves_the_dashboard(self, client):
        assert "laya-classifier" in client.get("/").text

    def test_screens_a_sample(self, client):
        result = client.post("/api/samples/scanned-document-exe.eml/screen").json()
        assert result["verdict"] == "quarantine"
        assert result["email"]["attachments"][0]["filename"] == "Scan_0928.pdf.exe"

    def test_screens_plain_fields(self, client):
        result = client.post("/api/screen", json={"from": "Boss <boss@freemail.example>", "subject": "Urgent",
                                                  "body": "Wire $9,000 today, keep it confidential."}).json()
        assert result["verdict"] == "quarantine"

    def test_screens_a_batch(self, client):
        raw = (SAMPLES / "colleague-meeting-notes.eml").read_text(encoding="utf-8")
        results = client.post("/api/screen/batch", json={"emails": [{"raw": raw}, {"body": "Lunch at noon?"}]}).json()
        assert [r["verdict"] for r in results] == ["deliver", "deliver"]

    def test_refuses_paths_outside_the_samples(self, client):
        assert client.post("/api/samples/..%2Fpyproject.toml/screen").status_code == 404

    def test_lists_samples(self, client):
        assert len(client.get("/api/samples").json()) == len(LABELS)


def test_config_defaults_protect_the_sample_org():
    assert ScreenerConfig().protected_domains == ["northwind.example"]
