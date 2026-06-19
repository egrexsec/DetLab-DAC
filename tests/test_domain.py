from pathlib import Path

import yaml

from detlab.domain import build_detection_catalog, build_detection_workspace, export_domain_schema
from detlab.models import Detection


SAMPLE_DETECTION = {
    "id": "DET-1234",
    "name": "Office Spawned PowerShell",
    "description": "Detects Office spawning PowerShell.",
    "logsource": {
        "product": "windows",
        "service": "sysmon",
    },
    "attack": {
        "technique": "T1059.001",
        "tactic": "execution",
    },
    "severity": "high",
    "status": "validated",
    "author": "Mell0wx",
    "domain": ["endpoint"],
    "platforms": ["windows"],
    "attack_context": [
        {
            "technique": "T1105",
            "tactic": "command-and-control",
            "name": "Ingress Tool Transfer",
            "coverage": "related",
            "rationale": "Payload retrieval commonly follows script execution.",
        }
    ],
    "data_sources": [
        {
            "name": "Sysmon Process Creation",
            "kind": "endpoint",
            "provider": "windows",
            "event_names": ["Event ID 1"],
        }
    ],
    "triage_steps": [
        {
            "step": "Review the Office parent process and user context.",
            "priority": "high",
        }
    ],
    "investigation_steps": [
        {
            "step": "Check for child processes and outbound connections.",
            "priority": "high",
        }
    ],
    "escalation_guidance": [
        "Escalate when Office launches encoded or network-connected PowerShell.",
    ],
    "hunt_suggestions": [
        {
            "name": "Office to script interpreter hunt",
            "hypothesis": "Users with one malicious spawn may have broader script abuse on the host.",
        }
    ],
    "artifacts": [
        {
            "name": "PowerShell operational log",
            "category": "event_log",
            "path": "Microsoft-Windows-PowerShell/Operational",
        }
    ],
    "velociraptor_artifacts": ["Windows.EventLogs.PowerShell"],
    "cloud_telemetry": [
        {
            "provider": "aws",
            "source": "CloudTrail",
            "event_names": ["SendCommand"],
        }
    ],
    "related_detections": [
        {
            "detection_id": "DET-5678",
            "relationship": "follow_on",
            "rationale": "PowerShell often leads into download activity.",
        }
    ],
    "response_actions": [
        {
            "title": "Isolate host",
            "priority": "high",
        }
    ],
    "references": ["https://attack.mitre.org/techniques/T1059/001/"],
    "falsepositives": ["Administrative macros"],
    "tests": [
        {
            "name": "Atomic",
            "source": "atomic-red-team",
            "test_id": "1",
        }
    ],
    "detection": {
        "selection": {
            "EventID": 1,
            "ParentImage|endswith": "\\WINWORD.EXE",
            "Image|endswith": "\\powershell.exe",
        },
        "condition": "selection",
    },
}


RELATED_DETECTION = {
    "id": "DET-5678",
    "title": "PowerShell Download Cradle",
    "description": "Detects PowerShell downloading remote content.",
    "logsource": {
        "product": "windows",
        "service": "sysmon",
    },
    "attack": {
        "technique": "T1105",
        "tactic": "command-and-control",
    },
    "severity": "high",
    "status": "testing",
    "author": "Mell0wx",
    "tests": [
        {
            "name": "Manual",
            "source": "lab",
            "test_id": "2",
        }
    ],
    "detection": {
        "selection": {
            "EventID": 1,
            "CommandLine|contains": ["Invoke-WebRequest", "DownloadString"],
        },
        "condition": "selection",
    },
}


def _write_detection(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def test_detection_model_accepts_detection_first_fields():
    detection = Detection.model_validate(SAMPLE_DETECTION)

    assert detection.title == "Office Spawned PowerShell"
    assert detection.name == "Office Spawned PowerShell"
    assert detection.attack_context[0].coverage == "related"
    assert detection.related_detections[0].detection_id == "DET-5678"
    assert detection.response_actions[0].title == "Isolate host"


def test_export_domain_schema_exposes_detection_entity():
    schema = export_domain_schema()

    assert schema["primary_entity"] == "Detection"
    assert "Detection" in schema["entities"]
    assert "RelatedDetection" in schema["entities"]


def test_build_detection_catalog_returns_detection_first_fields(tmp_path):
    _write_detection(tmp_path / "windows" / "office_spawned_powershell.yml", SAMPLE_DETECTION)
    _write_detection(tmp_path / "windows" / "download_cradle.yml", RELATED_DETECTION)

    catalog = build_detection_catalog(str(tmp_path))

    assert catalog["total"] == 2
    entry = next(item for item in catalog["detections"] if item["id"] == "DET-1234")
    assert entry["name"] == "Office Spawned PowerShell"
    assert entry["domain"] == ["endpoint"]
    assert entry["related_detections_count"] == 1
    assert entry["investigation_readiness_score"] > 0


def test_build_detection_workspace_returns_heat_map_and_relationship_graph(tmp_path):
    _write_detection(tmp_path / "windows" / "office_spawned_powershell.yml", SAMPLE_DETECTION)
    _write_detection(tmp_path / "windows" / "download_cradle.yml", RELATED_DETECTION)

    workspace = build_detection_workspace("DET-1234", str(tmp_path))

    assert workspace is not None
    assert workspace["detection"]["name"] == "Office Spawned PowerShell"
    assert workspace["overview"]["attack_mappings"]["primary"]["technique"] == "T1059.001"
    assert workspace["heat_map"]["direct"][0]["technique"] == "T1059.001"
    assert workspace["threat_hunting"]["related_detections"][0]["detection_id"] == "DET-5678"
    assert workspace["relationship_graph"]["edges"][0]["target"] == "DET-5678"
