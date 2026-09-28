"""Measure the screener on the labeled sample inbox with the real Laya checkpoints.

    python eval/evaluate.py                 # GPU when available
    python eval/evaluate.py --device cpu

Compares three screeners on the same emails, so each part's contribution shows:
signals only, Laya only, and the combined policy. Writes docs/evaluation.md.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from laya_screener.config import load_config  # noqa: E402
from laya_screener.engine import LayaEngine  # noqa: E402
from laya_screener.parse import parse_email  # noqa: E402
from laya_screener.policy import Thresholds, decide  # noqa: E402
from laya_screener.questions import email_state  # noqa: E402
from laya_screener.signals import find_signals, trusted_origin  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", default=None)
    parser.add_argument("--out", default=str(ROOT / "docs" / "evaluation.md"))
    args = parser.parse_args()

    labels = json.loads((ROOT / "samples" / "labels.json").read_text(encoding="utf-8"))
    config, thresholds = load_config(), Thresholds()
    engine = LayaEngine(device=args.device)
    engine.predict([{"body": "warm-up"}])

    rows = []
    for label in labels:
        mail = parse_email((ROOT / "samples" / label["file"]).read_bytes())
        start = time.perf_counter()
        [reading] = engine.predict([email_state(mail)])
        signals = find_signals(mail, config)
        decision = decide(reading.view, signals, trusted_origin(mail, config), thresholds)
        rows.append({
            "file": label["file"], "lang": label["lang"], "phishing": label["phishing"],
            "expected": label["verdict"], "verdict": decision.verdict,
            "laya_only": reading.view.risk >= thresholds.laya_sure,
            "signals_only": any(s.severity == "high" for s in signals),
            "flagged": decision.verdict != "deliver",
            "laya_risk": round(reading.view.risk, 3), "broad_phishing": round(reading.view.phishing, 3),
            "model": reading.model, "laya_ms": round(reading.latency_ms, 1),
            "total_ms": round((time.perf_counter() - start) * 1000, 1),
            "signals": [s.id for s in signals],
        })

    phish = [r for r in rows if r["phishing"]]
    legit = [r for r in rows if not r["phishing"]]

    def caught(key: str) -> str:
        return f"{sum(r[key] for r in phish)}/{len(phish)}"

    def false_alarms(key: str) -> str:
        return f"{sum(r[key] for r in legit)}/{len(legit)}"

    exact = sum(r["verdict"] == r["expected"] for r in rows)
    quarantined_legit = sum(r["verdict"] == "quarantine" for r in legit)
    by_model: dict[str, list[float]] = {}
    for r in rows:
        by_model.setdefault(r["model"], []).append(r["laya_ms"])

    lines = [
        "# Evaluation",
        "",
        f"Measured with `python eval/evaluate.py` on {engine.device} (laya {__import__('laya').__version__}),"
        f" over the {len(rows)} labeled emails in `samples/` ({len(phish)} attacks, {len(legit)} legitimate;"
        f" {sum(r['lang'] == 'en' for r in rows)} English, {sum(r['lang'] == 'pt' for r in rows)} Portuguese).",
        "This is a small, hand-made inbox: the numbers show how the parts work together, not how the",
        "screener does on real mail. Measure on your own labeled mail before trusting a threshold.",
        "",
        "| Screener | Attacks flagged | Legitimate mail flagged |",
        "|---|---|---|",
        f"| Signals only (any high-severity check) | {caught('signals_only')} | {false_alarms('signals_only')} |",
        f"| Laya only (risk >= {thresholds.laya_sure}) | {caught('laya_only')} | {false_alarms('laya_only')} |",
        f"| Combined policy (warn or quarantine) | {caught('flagged')} | {false_alarms('flagged')} |",
        "",
        f"Combined policy: {exact}/{len(rows)} verdicts exactly as labeled, {quarantined_legit} legitimate emails quarantined.",
        "",
        "| Checkpoint | Emails | Median Laya latency |",
        "|---|---|---|",
        *[f"| {m} | {len(v)} | {statistics.median(v):.0f} ms |" for m, v in sorted(by_model.items())],
        "",
        "| Email | Expected | Verdict | Laya risk | Broad phishing answer | Signals |",
        "|---|---|---|---|---|---|",
        *[f"| {r['file']} | {r['expected']} | {r['verdict']}{'' if r['verdict'] == r['expected'] else ' ✗'} |"
          f" {r['laya_risk']:.2f} | {r['broad_phishing']:.2f} | {', '.join(r['signals']) or '-'} |" for r in rows],
        "",
    ]
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(lines), encoding="utf-8")
    results_dir = ROOT / "eval" / "results"
    results_dir.mkdir(exist_ok=True)
    (results_dir / f"{engine.device}.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print("\n".join(lines[:22]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
