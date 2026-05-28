from detlab.kql import build_kql_query, export_kql_detection
from detlab.models import Detection


TEST_DETECTION = Detection.model_validate(
    {
        "id": "DET-0001",
        "title": "Encoded PowerShell Execution",
        "description": "Detects encoded PowerShell execution.",
        "logsource": {
            "product": "windows",
            "service": "process_creation",
        },
        "attack": {
            "technique": "T1059.001",
            "tactic": "execution",
        },
        "severity": "high",
        "status": "testing",
        "author": "Mell0wx",
        "tests": [
            {
                "name": "Atomic Test",
                "source": "atomic-red-team",
                "test_id": "T1059.001",
            }
        ],
        "detection": {
            "selection": {
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": ["-enc", "-encodedcommand"],
            },
            "condition": "selection",
        },
    }
)


def test_build_kql_query():
    query = build_kql_query(TEST_DETECTION)

    assert "DeviceProcessEvents" in query
    assert "ProcessCommandLine contains" in query
    assert "FolderPath endswith" in query


def test_export_kql_detection():
    exported = export_kql_detection(TEST_DETECTION)

    assert "// Detection ID: DET-0001" in exported
    assert "// ATT&CK: T1059.001" in exported
    assert "DeviceProcessEvents" in exported
