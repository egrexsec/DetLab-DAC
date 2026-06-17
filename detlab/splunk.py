from pathlib import Path

from detlab.models import Detection

FIELD_MAP = {
    "CommandLine": "process",
    "Image": "process_path",
    "EventID": "EventCode",
}


def _normalize_field(field: str) -> str:
    base = field.split("|")[0]
    return FIELD_MAP.get(base, base)


def _escape_value(value: str) -> str:
    return value.replace('\\', '\\\\').replace('"', '\\"')



def _render_value(field: str, value: str) -> str:
    escaped = _escape_value(value)
    if "contains" in field:
        return f'{_normalize_field(field)}="*{escaped}*"'

    if "endswith" in field:
        return f'{_normalize_field(field)}="*{escaped}"'

    return f'{_normalize_field(field)}="{escaped}"'


def build_splunk_search(detection: Detection) -> str:
    selection = detection.detection.selection

    query_parts = ["search"]

    for field, value in selection.items():
        if isinstance(value, list):
            conditions = [_render_value(field, item) for item in value]
            query_parts.append(f"({' OR '.join(conditions)})")
        else:
            query_parts.append(_render_value(field, str(value)))

    return " ".join(query_parts)


def export_splunk_detection(detection: Detection) -> str:
    spl = build_splunk_search(detection)

    metadata = [
        f"# Detection ID: {detection.id}",
        f"# Title: {detection.title}",
        f"# ATT&CK: {detection.attack.technique}",
        f"# Severity: {detection.severity}",
        f"# Status: {detection.status}",
        f"# Author: {detection.author}",
        "",
    ]

    return "\n".join(metadata) + spl + "\n"


def export_splunk_directory(detections: list[Detection], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    outputs = []

    for detection in detections:
        safe_name = detection.title.lower().replace(" ", "_")
        path = output_dir / f"{safe_name}.spl"
        path.write_text(export_splunk_detection(detection), encoding="utf-8")
        outputs.append(path)

    return outputs
