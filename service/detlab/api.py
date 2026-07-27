"""HTTP API for bounded server-side Sigma conversion."""
from __future__ import annotations

import asyncio
import os
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .converter import ConversionError, ConverterService

MAX_SOURCE_BYTES = 262_144


class ConvertRequest(BaseModel):
    source: str
    target: str


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def create_app(
    *,
    converter: Any | None = None,
    conversion_timeout_seconds: float = 5.0,
) -> FastAPI:
    service = converter or ConverterService()
    app = FastAPI(title="DetLab Sigma Conversion API", version="1.0.0")
    origins = [value.strip() for value in os.environ.get("DETLAB_CORS_ORIGINS", "http://localhost:3000").split(",") if value.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/backends")
    async def backends() -> dict[str, Any]:
        return {"backends": service.backends()}

    @app.post("/v1/convert")
    async def convert(request: ConvertRequest) -> dict[str, Any]:
        if len(request.source.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise _error(413, "source_too_large", f"Sigma source exceeds {MAX_SOURCE_BYTES} bytes")
        known_targets = {backend["id"] for backend in service.backends()}
        if request.target not in known_targets:
            raise _error(422, "unsupported_backend", "Requested conversion backend is not registered")
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(service.convert, request.source, request.target),
                timeout=conversion_timeout_seconds,
            )
        except TimeoutError as exc:
            raise _error(504, "conversion_timeout", "Conversion exceeded the configured timeout") from exc
        except ConversionError as exc:
            raise _error(422, "invalid_sigma", str(exc)) from exc

    return app


app = create_app()
