import json

from detlab.models import Detection
from detlab.navigator import generate_navigator_layer


TEST_DETECTION = Detection.model_validate(
    {
        "id": "DET-0001",
        "title": "Encoded PowerShell Execution",
        "description": "Detects PowerShell execution using encoded command arguments.",
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
                "Image|endswith": "\\powershell.exe"
            },
            "condition": "selection",
        },
    }
)


def test_generate_navigator_layer():
    content = generate_navigator_layer([TEST_DETECTION])

    parsed = json.loads(content)

    assert parsed["name"] == "DetLab ATT&CK Coverage"
    assert len(parsed["techniques"]) == 1
    assert parsed["techniques"][0]["techniqueID"] == "T1059.001"
    assert parsed["techniques"][0]["score"] == 75


def test_generate_navigator_layer_count_scoring():
    content = generate_navigator_layer([TEST_DETECTION], score_by="count")

    parsed = json.loads(content)

    assert parsed["techniques"][0]["score"] == 25
