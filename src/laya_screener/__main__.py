"""Command line: screen .eml files, or start the dashboard.

    laya-screener screen samples/*.eml
    laya-screener screen message.eml --json
    laya-screener serve --port 8000
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

COLORS = {"deliver": "\033[32m", "warn": "\033[33m", "quarantine": "\033[31m"}


def _screen(args: argparse.Namespace) -> int:
    from .engine import LayaEngine
    from .screen import Screener

    paths = [Path(p) for pattern in args.files for p in (glob.glob(pattern) or [pattern])]
    screener = Screener(LayaEngine(device=args.device, preload=False))
    results = screener.screen_many([p.read_bytes() for p in paths])
    if args.json:
        for path, result in zip(paths, results):
            print(json.dumps({"file": path.name, **result}, ensure_ascii=False))
        return 0
    color = sys.stdout.isatty()
    for path, r in zip(paths, results):
        verdict = r["verdict"]
        tag = f"{COLORS[verdict]}{verdict:<10}\033[0m" if color else f"{verdict:<10}"
        print(f"{tag} risk {r['risk']:>3}  {r['laya']['model']:<12} {r['laya']['latency_ms']:>5.0f} ms  {path.name}")
        for reason in r["reasons"][:3]:
            print(f"{'':12}- {reason}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    import os

    import uvicorn

    if args.device:
        os.environ["LAYA_DEVICE"] = args.device
    uvicorn.run("laya_screener.api:create_app", factory=True, host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="laya-screener", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--device", help="cuda, cpu or mps (default: cuda when available)")
    sub = parser.add_subparsers(dest="command", required=True)
    screen = sub.add_parser("screen", help="screen .eml files")
    screen.add_argument("files", nargs="+")
    screen.add_argument("--json", action="store_true", help="one JSON result per line")
    screen.set_defaults(run=_screen)
    serve = sub.add_parser("serve", help="start the API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(run=_serve)
    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
