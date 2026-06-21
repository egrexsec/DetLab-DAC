import re
from typing import Any

import yaml
from pydantic import ValidationError

from detlab.contracts import CANONICAL_MODEL_VERSION
from detlab.eql import export_eql_detection
from detlab.kql import export_kql_detection
from detlab.markdown_ingest import parse_markdown_detection_content
from detlab.models import Detection
from detlab.scoring import score_detection
from detlab.sigma_export import export_sigma_detection
from detlab.splunk import export_splunk_detection

SUPPORTED_CONVERSION_TARGETS = {"sigma", "splunk", "kql", "eql"}
DISALLOWED_QUERY_VALUE_CHARS = {'"', '\n', '\r'}
CONVERSION_METADATA_FIELDS = {"SourcePath", "ContentKind", "QueryLanguage", "QueryText", "QueryPreview", "SourceFormat", "NormalizedFrom"}
MARKDOWN_HINTS = ("```", "\n# ", "\n## ", "\n### ")


class UnsupportedConversionTargetError(ValueError):
    pass


def _normalize_validation_errors(exc: ValidationError) -> list[dict[str, Any]]:
    return [
        {
            "loc": list(error["loc"]),
            "msg": error["msg"],
            "type": error["type"],
        }
        for error in exc.errors()
    ]


def _load_detection_from_yaml(content: str) -> Detection:
    data = yaml.safe_load(content) or {}
    if not isinstance(data, dict):
        raise ValueError("Detection content must deserialize to a mapping")
    return Detection.model_validate(data)



def _looks_like_markdown_detection(content: str) -> bool:
    stripped = content.lstrip()
    has_frontmatter = stripped.startswith("---\n")
    has_markdown_structure = any(hint in content for hint in MARKDOWN_HINTS)
    return has_frontmatter and has_markdown_structure



def _detect_content_format(content: str) -> tuple[str, str]:
    if _looks_like_markdown_detection(content):
        return "markdown", "markdown_frontmatter"

    stripped = content.lstrip()
    if stripped.startswith("# Detection ID:") and "\nsearch" in content:
        return "splunk", "splunk_export"
    if stripped.startswith("// Detection ID:") and "process where" in content:
        return "eql", "eql_export"
    if stripped.startswith("// Detection ID:") and "| where" in content:
        return "kql", "kql_export"

    try:
        parsed = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        parsed = None

    if isinstance(parsed, dict):
        if {"title", "id", "logsource", "detection"}.issubset(parsed.keys()) and (
            "level" in parsed or "tags" in parsed or ("attack" not in parsed and "tests" not in parsed)
        ):
            return "sigma", "sigma_export"

    return "yaml", "canonical_yaml"



def _processing_metadata(content: str) -> dict[str, str]:
    source_format, normalized_from = _detect_content_format(content)
    return {
        "source_format": source_format,
        "normalized_from": normalized_from,
        "canonical_model_version": CANONICAL_MODEL_VERSION,
    }



SPLUNK_IMPORT_FIELD_MAP = {
    "process": "CommandLine",
    "process_path": "Image",
    "EventCode": "EventID",
}
KQL_IMPORT_FIELD_MAP = {
    "ProcessCommandLine": "CommandLine",
    "FolderPath": "Image",
    "EventID": "EventID",
}
EQL_IMPORT_FIELD_MAP = {
    "process.command_line": "CommandLine",
    "process.executable": "Image",
    "event.code": "EventID",
}
KQL_TABLE_PRODUCT_MAP = {
    "DeviceProcessEvents": "windows",
    "DeviceEvents": "windows",
}



def _extract_export_metadata(content: str, prefix: str) -> tuple[dict[str, str], str]:
    metadata: dict[str, str] = {}
    lines = content.splitlines()
    body_start = 0
    for index, line in enumerate(lines):
        if not line.strip():
            body_start = index + 1
            break
        if not line.startswith(prefix):
            body_start = index
            break
        raw = line[len(prefix) :].strip()
        if ":" in raw:
            key, value = raw.split(":", 1)
            metadata[key.strip()] = value.strip()
    else:
        body_start = len(lines)
    body = "\n".join(lines[body_start:]).strip()
    return metadata, body



def _decode_export_value(value: str) -> str:
    return value.replace('\\"', '"').replace('\\\\', '\\')



def _append_selection_value(selection: dict[str, Any], field: str, value: Any) -> None:
    existing = selection.get(field)
    if existing is None:
        selection[field] = value
        return
    if isinstance(existing, list):
        existing.append(value)
        return
    selection[field] = [existing, value]



def _selection_key(field: str, operator: str) -> str:
    if operator == "contains":
        return f"{field}|contains"
    if operator == "endswith":
        return f"{field}|endswith"
    return field



def _base_detection_payload(metadata: dict[str, str], selection: dict[str, Any], *, default_product: str = "windows") -> dict[str, Any]:
    detection_id = metadata.get("Detection ID") or metadata.get("id") or "DET-0000"
    title = metadata.get("Title") or metadata.get("title") or detection_id
    return {
        "id": detection_id,
        "title": title,
        "name": title,
        "description": metadata.get("Description") or f"Imported detection authored as rendered content for {title}.",
        "logsource": {
            "product": metadata.get("Product") or default_product,
            "service": metadata.get("Service") or "imported",
        },
        "attack": {
            "technique": metadata.get("ATT&CK") or "T0000",
            "tactic": metadata.get("Tactic") or "unknown",
        },
        "severity": metadata.get("Severity") or "medium",
        "status": metadata.get("Status") or "experimental",
        "author": metadata.get("Author") or "imported",
        "references": [],
        "falsepositives": [],
        "tests": [
            {
                "name": f"Imported {title}",
                "source": "rendered-import",
                "test_id": detection_id,
            }
        ],
        "detection": {
            "selection": selection,
            "condition": "selection",
        },
    }



def _parse_sigma_detection(content: str) -> Detection:
    data = yaml.safe_load(content) or {}
    if not isinstance(data, dict):
        raise ValueError("Sigma content must deserialize to a mapping")
    tags = [str(tag) for tag in data.get("tags", []) if isinstance(tag, str)]
    tactic = next((tag.split("attack.", 1)[1].replace("_", "-") for tag in tags if tag.startswith("attack.") and not re.match(r"attack\.t\d{4}", tag)), "unknown")
    technique = next((tag.split("attack.", 1)[1].upper() for tag in tags if re.match(r"attack\.t\d{4}(?:\.\d{3})?$", tag)), "T0000")
    payload = {
        "id": data.get("id") or "DET-0000",
        "title": data.get("title") or data.get("id") or "Imported Sigma Detection",
        "description": data.get("description") or "Imported from Sigma content.",
        "logsource": data.get("logsource") or {"product": "windows", "service": "imported"},
        "attack": {
            "technique": technique,
            "tactic": tactic,
        },
        "severity": data.get("level") or "medium",
        "status": data.get("status") or "experimental",
        "author": data.get("author") or "imported",
        "references": data.get("references") or [],
        "falsepositives": data.get("falsepositives") or [],
        "tests": [
            {
                "name": f"Imported {data.get('title') or data.get('id') or 'sigma'}",
                "source": "sigma-import",
                "test_id": data.get("id") or "DET-0000",
            }
        ],
        "detection": data.get("detection") or {"selection": {}, "condition": "selection"},
    }
    return Detection.model_validate(payload)



def _parse_splunk_selection(query: str) -> dict[str, Any]:
    selection: dict[str, Any] = {}
    for field, raw_value in re.findall(r'([A-Za-z0-9_.]+)="((?:\\.|[^\"])*)"', query):
        mapped = str(SPLUNK_IMPORT_FIELD_MAP.get(field, field))
        value = _decode_export_value(raw_value)
        operator = "exact"
        if value.startswith("*") and value.endswith("*") and len(value) >= 2:
            operator = "contains"
            value = value[1:-1]
        elif value.startswith("*"):
            operator = "endswith"
            value = value[1:]
        key = _selection_key(mapped, operator)
        parsed_value: Any = int(value) if mapped == "EventID" and value.isdigit() else value
        _append_selection_value(selection, key, parsed_value)
    return selection



def _parse_kql_selection(query: str) -> tuple[str, dict[str, Any]]:
    lines = [line.strip() for line in query.splitlines() if line.strip()]
    table = lines[0] if lines else "DeviceEvents"
    selection: dict[str, Any] = {}
    for field, operator, raw_value in re.findall(r'([A-Za-z0-9_.]+)\s+(contains|endswith|==)\s+"((?:\\.|[^\"])*)"', query):
        mapped = str(KQL_IMPORT_FIELD_MAP.get(field, field))
        value = _decode_export_value(raw_value)
        key = _selection_key(mapped, "contains" if operator == "contains" else "endswith" if operator == "endswith" else "exact")
        parsed_value: Any = int(value) if mapped == "EventID" and value.isdigit() else value
        _append_selection_value(selection, key, parsed_value)
    return table, selection



def _parse_eql_selection(query: str) -> dict[str, Any]:
    selection: dict[str, Any] = {}
    for field, operator, raw_value in re.findall(r'([A-Za-z0-9_.]+)\s+(like|==)\s+"((?:\\.|[^\"])*)"', query):
        mapped = str(EQL_IMPORT_FIELD_MAP.get(field, field))
        value = _decode_export_value(raw_value)
        resolved_operator = "exact"
        if operator == "like" and value.startswith("*") and value.endswith("*") and len(value) >= 2:
            resolved_operator = "contains"
            value = value[1:-1]
        elif operator == "like" and value.startswith("*"):
            resolved_operator = "endswith"
            value = value[1:]
        key = _selection_key(mapped, resolved_operator)
        parsed_value: Any = int(value) if mapped == "EventID" and value.isdigit() else value
        _append_selection_value(selection, key, parsed_value)
    return selection



def _load_detection_from_rendered_content(content: str) -> Detection | None:
    stripped = content.lstrip()
    if stripped.startswith("# Detection ID:") and "\nsearch" in content:
        metadata, body = _extract_export_metadata(content, "#")
        return Detection.model_validate(_base_detection_payload(metadata, _parse_splunk_selection(body)))
    if stripped.startswith("// Detection ID:") and "process where" in content:
        metadata, body = _extract_export_metadata(content, "//")
        return Detection.model_validate(_base_detection_payload(metadata, _parse_eql_selection(body), default_product=metadata.get("Product") or "windows"))
    if stripped.startswith("// Detection ID:") and "| where" in content:
        metadata, body = _extract_export_metadata(content, "//")
        table, selection = _parse_kql_selection(body)
        return Detection.model_validate(
            _base_detection_payload(metadata, selection, default_product=KQL_TABLE_PRODUCT_MAP.get(table, metadata.get("Product") or "windows"))
        )
    try:
        parsed = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        parsed = None
    if isinstance(parsed, dict) and {"title", "id", "logsource", "detection"}.issubset(parsed.keys()):
        return _parse_sigma_detection(content)
    return None



def _load_detection_from_content(content: str) -> Detection:
    try:
        return _load_detection_from_yaml(content)
    except (ValidationError, yaml.YAMLError, ValueError) as yaml_error:
        imported_detection = _load_detection_from_rendered_content(content)
        if imported_detection is not None:
            return imported_detection
        if not _looks_like_markdown_detection(content):
            raise yaml_error
        markdown_detection = parse_markdown_detection_content(content)
        if markdown_detection is not None:
            return markdown_detection
        raise yaml_error



def _normalize_processing_error(location: list[str], message: str, error_type: str) -> dict[str, Any]:
    return {
        "loc": location,
        "msg": message,
        "type": error_type,
    }



def _iter_selection_values(selection: dict[str, Any]):
    for field, value in selection.items():
        if isinstance(value, list):
            for index, item in enumerate(value):
                yield ["detection", "selection", field, index], str(item)
        else:
            yield ["detection", "selection", field], str(value)



def _validate_conversion_safe_values(detection: Detection) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    for location, value in _iter_selection_values(detection.detection.selection):
        field_name = str(location[2]) if len(location) > 2 else ""
        if field_name in CONVERSION_METADATA_FIELDS:
            continue
        if any(char in value for char in DISALLOWED_QUERY_VALUE_CHARS):
            errors.append(
                _normalize_processing_error(
                    location,
                    'conversion preview does not support double quotes or multiline values in detection selectors',
                    'unsafe_conversion_value',
                )
            )
    return errors


def inspect_detection_content(content: str) -> dict[str, Any]:
    metadata = _processing_metadata(content)
    try:
        detection = _load_detection_from_content(content)
    except ValidationError as exc:
        return {
            "valid": False,
            "errors": _normalize_validation_errors(exc),
            **metadata,
        }
    except yaml.YAMLError as exc:
        return {
            "valid": False,
            "errors": [{"loc": ["content"], "msg": str(exc), "type": "yaml_error"}],
            **metadata,
        }
    except ValueError as exc:
        return {
            "valid": False,
            "errors": [{"loc": ["content"], "msg": str(exc), "type": "value_error"}],
            **metadata,
        }

    return {
        "valid": True,
        "errors": [],
        "detection": detection.model_dump(),
        "score": score_detection(detection),
        **metadata,
    }


def convert_detection_content(content: str, target: str) -> dict[str, Any]:
    normalized_target = target.lower()
    if normalized_target not in SUPPORTED_CONVERSION_TARGETS:
        raise UnsupportedConversionTargetError(f"Unsupported conversion target: {target}")

    inspection = inspect_detection_content(content)
    if not inspection["valid"]:
        return inspection

    detection = _load_detection_from_content(content)
    conversion_errors = _validate_conversion_safe_values(detection)
    if conversion_errors:
        return {
            **inspection,
            "valid": False,
            "errors": conversion_errors,
        }

    rendered = {
        "sigma": export_sigma_detection(detection),
        "splunk": export_splunk_detection(detection),
        "kql": export_kql_detection(detection),
        "eql": export_eql_detection(detection),
    }[normalized_target]

    return {
        **inspection,
        "target": normalized_target,
        "content": rendered,
    }
