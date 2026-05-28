from detlab.eql import build_eql_query, export_eql_detection
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


def test_build_eql_query():
    query = build_eql_query(TEST_DETECTION)

    assert "process where" in query
    assert "process.command_line like" in query
    assert "process.executable like" in query


def test_export_eql_detection():
    exported = export_eql_detection(TEST_DETECTION)

    assert "// Detection ID: DET-0001" in exported
    assert "// ATT&CK: T1059.001" in exported
    assert "process where" in exported
