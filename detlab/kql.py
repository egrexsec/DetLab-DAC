from pathlib import Path

from detlab.models import Detection

FIELD_MAP = {
    "CommandLine": "ProcessCommandLine",
    "Image": "FolderPath",
    "EventID": "EventID",
}

TABLE_MAP = {
    "windows": "DeviceProcessEvents",
    "linux": "DeviceProcessEvents",
    "macos": "DeviceProcessEvents",
}


def _normalize_field(field: str) -> str:
    base = field.split("|")[0]
    return FIELD_MAP.get(base, base)


def _escape_value(value: str) -> str:
    return value.replace('\\', '\\\\').replace('"', '\\"')



def _render_condition(field: str, value: str) -> str:
    normalized = _normalize_field(field)
    escaped = _escape_value(value)

    if "contains" in field:
        return f'{normalized} contains "{escaped}"'

    if "endswith" in field:
        return f'{normalized} endswith "{escaped}"'

    return f'{normalized} == "{escaped}"'



def build_kql_query(detection: Detection) -> str:
    table = TABLE_MAP.get(detection.logsource.product, "DeviceEvents")
    selection = detection.detection.selection

    query_lines = [table]

    conditions = []

    for field, value in selection.items():
        if isinstance(value, list):
            rendered = [_render_condition(field, item) for item in value]
            conditions.append(f"({' or '.join(rendered)})")
        else:
            conditions.append(_render_condition(field, str(value)))

    if conditions:
        query_lines.append(f"| where {' and '.join(conditions)}")

    return "\n".join(query_lines)



def export_kql_detection(detection: Detection) -> str:
    metadata = [
        f"// Detection ID: {detection.id}",
        f"// Title: {detection.title}",
        f"// Description: {detection.description}",
        f"// ATT&CK: {detection.attack.technique}",
        f"// Tactic: {detection.attack.tactic}",
        f"// Product: {detection.logsource.product}",
        f"// Service: {detection.logsource.service}",
        f"// Severity: {detection.severity}",
        f"// Status: {detection.status}",
        f"// Author: {detection.author}",
        "",
    ]

    return "\n".join(metadata) + build_kql_query(detection) + "\n"



def export_kql_directory(detections: list[Detection], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    outputs = []

    for detection in detections:
        safe_name = detection.title.lower().replace(" ", "_")
        path = output_dir / f"{safe_name}.kql"
        path.write_text(export_kql_detection(detection), encoding="utf-8")
        outputs.append(path)

    return outputs
