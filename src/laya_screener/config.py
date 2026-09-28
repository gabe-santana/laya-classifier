"""Who the screener protects. Lookalike checks compare against these domains."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "config" / "screener.json"


@dataclass
class ScreenerConfig:
    # The organization's own domains: mail claiming to be from them is held to a higher bar.
    protected_domains: list[str] = field(default_factory=lambda: ["northwind.example"])
    # Partners and vendors the organization really deals with, also targets for lookalikes.
    trusted_domains: list[str] = field(default_factory=list)
    # Names attackers put in a display name to borrow authority.
    protected_names: list[str] = field(default_factory=lambda: ["northwind"])
    executive_names: list[str] = field(default_factory=list)
    shorteners: list[str] = field(default_factory=lambda: ["bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy"])

    @property
    def known_domains(self) -> list[str]:
        return [*self.protected_domains, *self.trusted_domains]


def load_config(path: str | os.PathLike[str] | None = None) -> ScreenerConfig:
    """Reads LAYA_SCREENER_CONFIG (or config/screener.json) when present, else the defaults."""
    target = Path(path or os.environ.get("LAYA_SCREENER_CONFIG") or DEFAULT_CONFIG)
    if not target.exists():
        return ScreenerConfig()
    data = json.loads(target.read_text(encoding="utf-8"))
    return ScreenerConfig(**data)
