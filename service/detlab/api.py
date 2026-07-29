"""HTTP API for bounded server-side Sigma conversion."""
from __future__ import annotations

import asyncio
import json
import multiprocessing
import os
import queue
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .converter import ConversionError, ConverterService

MAX_SOURCE_BYTES = 262_144


class ConversionWorkerError(RuntimeError):
    """Raised when an isolated conversion worker cannot return a complete result."""


def _conversion_worker(result_queue: Any, service: Any, source: str, target: str) -> None:
    try:
        # Serialize before publishing so callers can never observe partial output.
        payload = json.dumps(service.convert(source, target), separators=(",", ":"))
        result_queue.put(("ok", payload))
    except ConversionError as exc:
        result_queue.put(("conversion_error", str(exc)))
    except Exception:
        result_queue.put(("worker_error", "Conversion worker failed"))


def _convert_isolated(service: Any, source: str, target: str, timeout: float) -> dict[str, Any]:
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue(maxsize=1)
    process = context.Process(
        target=_conversion_worker,
        args=(result_queue, service, source, target),
        daemon=True,
    )
    process.start()
    deadline = time.monotonic() + timeout
    try:
        try:
            status, payload = result_queue.get(timeout=max(0.0, deadline - time.monotonic()))
        except queue.Empty as exc:
            if process.is_alive():
                raise TimeoutError("conversion timed out") from exc
            raise ConversionWorkerError("Conversion worker returned no result") from exc

        process.join(max(0.0, deadline - time.monotonic()))
        if process.is_alive():
            raise TimeoutError("conversion timed out")
    finally:
        if process.is_alive():
            process.terminate()
            process.join(0.5)
            if process.is_alive():
                process.kill()
                process.join()
        result_queue.close()
        result_queue.join_thread()
    if status == "conversion_error":
        raise ConversionError(payload)
    if status != "ok":
        raise ConversionWorkerError(payload)
    try:
        result = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ConversionWorkerError("Conversion worker returned an invalid result") from exc
    if not isinstance(result, dict):
        raise ConversionWorkerError("Conversion worker returned an invalid result")
    return result


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
            return await asyncio.to_thread(
                _convert_isolated,
                service,
                request.source,
                request.target,
                conversion_timeout_seconds,
            )
        except TimeoutError as exc:
            raise _error(504, "conversion_timeout", "Conversion exceeded the configured timeout") from exc
        except ConversionError as exc:
            raise _error(422, "invalid_sigma", str(exc)) from exc
        except ConversionWorkerError as exc:
            raise _error(500, "conversion_failed", "Conversion worker failed safely") from exc

    return app


app = create_app()
