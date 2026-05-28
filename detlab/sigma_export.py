from pathlib import Path

import yaml

from detlab.models import Detection

TACTIC_TO_TAG = {
    "initial-access": "attack.initial_access",
    "execution": "attack.execution",
    "persistence": "attack.persistence",
    "privilege-escalation": "attack.privilege_escalation",
    "defense-evasion": "attack.defense_evasion",
    "credential-access": "attack.credential_access",
    "discovery": "attack.discovery",
    "lateral-movement": "attack.lateral_movement",
    "collection": "attack.collection",
    "exfiltration": "attack.exfiltration",
    "command-and-control": "attack.command_and_control",
    "impact": "attack.impact",
}



def detection_to_sigma(detection: Detection) -> dict:
    tags = [
        TACTIC_TO_TAG.get(detection.attack.tactic, f"attack.{detection.attack.tactic}"),
        f"attack.{detection.attack.technique.lower()}",
    ]

    return {
        "title": detection.title,
        "id": detection.id,
        "status": detection.status,
        "description": detection.description,
        "author": detection.author,
        "references": detection.references,
        "falsepositives": detection.falsepositives,
        "level": detection.severity,
        "tags": tags,
        "logsource": {
            "product": detection.logsource.product,
            "service": detection.logsource.service,
        },
        "detection": detection.detection,
    }



def export_sigma_detection(detection: Detection) -> str:
    return yaml.safe_dump(detection_to_sigma(detection), sort_keys=False)



def export_sigma_directory(detections: list[Detection], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    outputs = []

    for detection in detections:
        safe_name = detection.title.lower().replace(" ", "_")
        path = output_dir / f"{safe_name}.yml"
        path.write_text(export_sigma_detection(detection), encoding="utf-8")
        outputs.append(path)

    return outputs
