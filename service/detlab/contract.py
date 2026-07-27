"""Adapters for DetLab Detection Content Specification v1."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

SPEC_VERSION = "1.0.0"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _as_authors(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return [str(item).strip() for item in values if str(item).strip()]


def normalize_detlab_detection(detection: Mapping[str, Any], source_path: Path | str, source_bytes: bytes) -> dict[str, Any]:
    canonical = detection.get("canonical_detection") or {}
    analytics = canonical.get("analytics") or {}
    logic = dict(analytics.get("logic") or {})
    condition = str(analytics.get("condition") or logic.pop("condition", "")).strip()
    attack = canonical.get("attack") or {}
    primary = attack.get("primary") or {}
    related = attack.get("related") or []
    techniques = sorted({str(item.get("technique")) for item in [primary, *related] if item.get("technique")})
    tactics = sorted({str(item.get("tactic")).lower().replace("_", "-") for item in [primary, *related] if item.get("tactic")})
    logsource = {key: str(value) for key, value in (canonical.get("logsource") or {}).items() if key in {"product", "category", "service"} and value}
    platforms = [str(value).lower().replace(" ", "-") for value in detection.get("platforms", []) if str(value).strip()]
    if not platforms:
        platforms = [str(logsource.get("product", "unknown")).lower().replace(" ", "-")]
    return {
        "spec_version": SPEC_VERSION,
        "kind": "detection",
        "id": str(detection.get("id", "")).strip(),
        "title": str(detection.get("title", "")).strip(),
        "description": str(detection.get("description", "")).strip(),
        "status": str(detection.get("status", "draft")).lower(),
        "severity": str(detection.get("severity", "unknown")).lower(),
        "authors": _as_authors(detection.get("author", "unknown")),
        "platforms": sorted(set(platforms)),
        "attack": {"techniques": techniques, "tactics": tactics},
        "logsource": logsource,
        "logic": {"format": "detlab-canonical", "body": logic, "condition": condition},
        "source": {
            "format": "detlab-canonical",
            "path": Path(source_path).as_posix(),
            "sha256": _sha256(source_bytes),
            "canonical": True,
        },
    }


def build_generated_artifact(
    normalized: Mapping[str, Any],
    *,
    target: str,
    language: str,
    content: str,
    converter: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "target": target,
        "language": language,
        "content": content,
        "content_sha256": _sha256(content.encode("utf-8")),
        "provenance": {
            "source_sha256": str(normalized["source"]["sha256"]),
            "spec_version": SPEC_VERSION,
            "converter": {"name": str(converter["name"]), "version": str(converter["version"])},
        },
    }


def generated_artifact_is_stale(normalized: Mapping[str, Any], artifact: Mapping[str, Any]) -> bool:
    provenance = artifact.get("provenance") or {}
    return (
        provenance.get("source_sha256") != normalized.get("source", {}).get("sha256")
        or provenance.get("spec_version") != SPEC_VERSION
    )
