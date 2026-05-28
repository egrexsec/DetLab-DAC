from pathlib import Path

from detlab.models import Detection

FIELD_MAP = {
    "CommandLine": "process.command_line",
    "Image": "process.executable",
    "EventID": "event.code",
}


def _normalize_field(field: str) -> str:
    return FIELD_MAP.get(field.split("|")[0], field.split("|")[0])



def _render_condition(field: str, value: str) -> str:
    normalized = _normalize_field(field)

    if "contains" in field:
        return f'{normalized} like "*{value}*"'

    if "endswith" in field:
        return f'{normalized} like "*{value}"'

    return f'{normalized} == "{value}"'



def build_eql_query(detection: Detection) -> str:
    selection = detection.detection.get("selection", {})

    conditions = []

    for field, value in selection.items():
        if isinstance(value, list):
            rendered = [_render_condition(field, item) for item in value]
            conditions.append(f"({' or '.join(rendered)})")
        else:
            conditions.append(_render_condition(field, str(value)))

    condition_block = " and ".join(conditions)

    return f'process where {condition_block}'



def export_eql_detection(detection: Detection) -> str:
    metadata = [
        f'// Detection ID: {detection.id}',
        f'// Title: {detection.title}',
        f'// ATT&CK: {detection.attack.technique}',
        f'// Severity: {detection.severity}',
        f'// Status: {detection.status}',
        f'// Author: {detection.author}',
        '',
    ]

    return '\n'.join(metadata) + build_eql_query(detection) + '\n'



def export_eql_directory(detections: list[Detection], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    outputs = []

    for detection in detections:
        safe_name = detection.title.lower().replace(' ', '_')
        path = output_dir / f'{safe_name}.eql'
        path.write_text(export_eql_detection(detection), encoding='utf-8')
        outputs.append(path)

    return outputs
