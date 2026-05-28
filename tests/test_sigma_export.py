from detlab.models import Detection
from detlab.sigma_export import detection_to_sigma, export_sigma_detection


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
        "references": [
            "https://attack.mitre.org/techniques/T1059/001/"
        ],
        "falsepositives": [
            "Administrative scripts"
        ],
        "tests": [
            {
                "name": "Atomic Test",
                "source": "atomic-red-team",
                "test_id": "T1059.001",
            }
        ],
        "detection": {
            "selection": {
                "CommandLine|contains": "-enc"
            },
            "condition": "selection",
        },
    }
)


def test_detection_to_sigma():
    sigma = detection_to_sigma(TEST_DETECTION)

    assert sigma["title"] == "Encoded PowerShell Execution"
    assert "attack.execution" in sigma["tags"]
    assert "attack.t1059.001" in sigma["tags"]
    assert sigma["level"] == "high"



def test_export_sigma_detection():
    exported = export_sigma_detection(TEST_DETECTION)

    assert "title: Encoded PowerShell Execution" in exported
    assert "attack.execution" in exported
    assert "attack.t1059.001" in exported
