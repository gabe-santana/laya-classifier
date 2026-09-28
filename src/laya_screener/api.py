"""HTTP API and dashboard. Run with `laya-screener serve` (or `python -m laya_screener serve`)."""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .engine import Engine
from .parse import parse_email
from .screen import Screener, compose_email

STATIC = Path(__file__).parent / "static"
SAMPLES = Path(os.environ.get("LAYA_SCREENER_SAMPLES", Path(__file__).resolve().parents[2] / "samples"))


class ScreenRequest(BaseModel):
    raw: str | None = Field(None, description="The full RFC 5322 message, headers included.")
    sender: str | None = Field(None, alias="from")
    subject: str | None = None
    body: str | None = None

    model_config = {"populate_by_name": True}

    def message(self) -> str:
        if self.raw:
            return self.raw
        if not self.body:
            raise HTTPException(422, "Send `raw`, or at least a `body`.")
        return compose_email(self.sender or "", self.subject or "", self.body)


class BatchRequest(BaseModel):
    emails: list[ScreenRequest] = Field(..., min_length=1, max_length=100)


@lru_cache
def default_screener() -> Screener:
    from .engine import LayaEngine

    return Screener(LayaEngine(device=os.environ.get("LAYA_DEVICE") or None))


def create_app(screener: Screener | None = None) -> FastAPI:
    get_screener = (lambda: screener) if screener else default_screener

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        get_screener()  # starts loading the checkpoints in the background
        yield

    app = FastAPI(title="laya-classifier", version=__version__, lifespan=lifespan,
                  description="Email security screener: Laya reads the text, code checks the evidence.")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/api/health")
    def health(s: Screener = Depends(get_screener)) -> dict[str, Any]:
        engine: Engine = s.engine
        return {"ready": engine.ready, "device": engine.device, "version": __version__}

    @app.post("/api/screen")
    def screen(request: ScreenRequest, s: Screener = Depends(get_screener)) -> dict[str, Any]:
        return s.screen(request.message())

    @app.post("/api/screen/batch")
    def screen_batch(request: BatchRequest, s: Screener = Depends(get_screener)) -> list[dict[str, Any]]:
        return s.screen_many([item.message() for item in request.emails])

    @app.get("/api/samples")
    def samples() -> list[dict[str, str]]:
        labels = json.loads((SAMPLES / "labels.json").read_text(encoding="utf-8"))
        out = []
        for label in labels:
            mail = parse_email((SAMPLES / label["file"]).read_bytes())
            out.append({"file": label["file"], "lang": label["lang"], "from": mail.sender.address,
                        "from_name": mail.sender.name, "subject": mail.subject})
        return out

    @app.post("/api/samples/{name}/screen")
    def screen_sample(name: str, s: Screener = Depends(get_screener)) -> dict[str, Any]:
        path = (SAMPLES / name).resolve()
        if path.parent != SAMPLES.resolve() or path.suffix != ".eml" or not path.exists():
            raise HTTPException(404, "No such sample.")
        return s.screen(path.read_bytes())

    return app
