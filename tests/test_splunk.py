from detlab.models import Detection
from detlab.splunk import build_splunk_search, export_splunk_detection


TEST_DETECTION = Detection.model_validate(
    {
        "id": "DET-0001",
        "title": "Encoded PowerShell Execution",
        "description": "Detects encoded PowerShell.",
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


def test_build_splunk_search():
    search = build_splunk_search(TEST_DETECTION)

    assert "search" in search
    assert "process_path" in search
    assert "process" in search
    assert "-enc" in search


def test_export_splunk_detection():
    exported = export_splunk_detection(TEST_DETECTION)

    assert "# Detection ID: DET-0001" in exported
    assert "# ATT&CK: T1059.001" in exported
    assert "search" in exported
