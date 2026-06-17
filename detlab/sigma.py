from pathlib import Path
from typing import Any

import yaml

from detlab.models import Detection

SEVERITY_MAP = {
    "informational": "low",
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

STATUS_MAP = {
    "experimental": "experimental",
    "test": "testing",
    "testing": "testing",
    "stable": "stable",
    "deprecated": "deprecated",
}

TACTIC_MAP = {
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
    "TA0042": "resource-development",
    "TA0043": "reconnaissance",
}


def _normalize_text(value: Any, fallback: str) -> str:
    if value is None:
        return fallback
    return str(value).strip() or fallback


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _extract_attack_tags(tags: list[str]) -> tuple[str, str]:
    technique = "T0000"
    tactic = "execution"

    for tag in tags:
        normalized = tag.lower().replace("attack.", "").strip()
        if normalized.startswith("t") and len(normalized) >= 5:
            technique = normalized.upper()
        elif normalized.upper() in TACTIC_MAP:
            tactic = TACTIC_MAP[normalized.upper()]
        elif normalized.startswith("ta"):
            tactic = TACTIC_MAP.get(normalized.upper(), tactic)
        elif normalized:
            tactic = normalized.replace("_", "-")

    return technique, tactic


def _next_detection_id(index: int, start: int) -> str:
    return f"DET-{start + index:04d}"


def sigma_rule_to_detection(rule: dict[str, Any], detection_id: str) -> dict[str, Any]:
    tags = _normalize_list(rule.get("tags"))
    technique, tactic = _extract_attack_tags(tags)

    level = str(rule.get("level", "medium")).lower()
    severity = SEVERITY_MAP.get(level, "medium")

    status_value = str(rule.get("status", "experimental")).lower()
    status = STATUS_MAP.get(status_value, "experimental")

    logsource = rule.get("logsource") or {}
    detection_logic = rule.get("detection") or {}
    selection = detection_logic.get("selection", detection_logic)

    converted = {
        "id": detection_id,
        "title": _normalize_text(rule.get("title"), "Imported Sigma Rule"),
        "description": _normalize_text(rule.get("description"), "Imported from Sigma rule."),
        "logsource": {
            "product": _normalize_text(logsource.get("product"), "unknown"),
            "service": _normalize_text(
                logsource.get("service") or logsource.get("category"), "unknown"
            ),
        },
        "attack": {
            "technique": technique,
            "tactic": tactic,
        },
        "severity": severity,
        "status": status,
        "author": _normalize_text(rule.get("author"), "unknown"),
        "references": _normalize_list(rule.get("references")),
        "falsepositives": _normalize_list(rule.get("falsepositives")),
        "tests": [
            {
                "name": "Imported Sigma rule validation reference",
                "source": "sigma",
                "test_id": _normalize_text(rule.get("id"), detection_id),
            }
        ],
        "detection": {
            "selection": selection,
            "condition": _normalize_text(detection_logic.get("condition"), "selection"),
        },
    }

    Detection.model_validate(converted)
    return converted


def import_sigma_file(path: Path, output_dir: Path, detection_id: str) -> Path:
    with path.open("r", encoding="utf-8") as handle:
        rule = yaml.safe_load(handle) or {}

    detection = sigma_rule_to_detection(rule, detection_id)
    output_dir.mkdir(parents=True, exist_ok=True)

    safe_name = path.stem.lower().replace(" ", "_")
    output_path = output_dir / f"{safe_name}.yml"
    output_path.write_text(yaml.safe_dump(detection, sort_keys=False), encoding="utf-8")
    return output_path


def import_sigma_dir(input_dir: Path, output_dir: Path, start_id: int = 1000) -> list[Path]:
    files = sorted([*input_dir.rglob("*.yml"), *input_dir.rglob("*.yaml")])
    outputs = []

    for index, file in enumerate(files):
        outputs.append(import_sigma_file(file, output_dir, _next_detection_id(index, start_id)))

    return outputs
