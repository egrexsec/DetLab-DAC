from typing import Any

import yaml
from pydantic import ValidationError

from detlab.models import Detection
from detlab.eql import export_eql_detection
from detlab.kql import export_kql_detection
from detlab.scoring import score_detection
from detlab.sigma_export import export_sigma_detection
from detlab.splunk import export_splunk_detection

SUPPORTED_CONVERSION_TARGETS = {"sigma", "splunk", "kql", "eql"}
DISALLOWED_QUERY_VALUE_CHARS = {'"', '\n', '\r'}


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
    try:
        detection = _load_detection_from_yaml(content)
    except ValidationError as exc:
        return {
            "valid": False,
            "errors": _normalize_validation_errors(exc),
        }
    except yaml.YAMLError as exc:
        return {
            "valid": False,
            "errors": [{"loc": ["content"], "msg": str(exc), "type": "yaml_error"}],
        }
    except ValueError as exc:
        return {
            "valid": False,
            "errors": [{"loc": ["content"], "msg": str(exc), "type": "value_error"}],
        }

    return {
        "valid": True,
        "errors": [],
        "detection": detection.model_dump(),
        "score": score_detection(detection),
    }


def convert_detection_content(content: str, target: str) -> dict[str, Any]:
    normalized_target = target.lower()
    if normalized_target not in SUPPORTED_CONVERSION_TARGETS:
        raise UnsupportedConversionTargetError(f"Unsupported conversion target: {target}")

    inspection = inspect_detection_content(content)
    if not inspection["valid"]:
        return inspection

    detection = _load_detection_from_yaml(content)
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
