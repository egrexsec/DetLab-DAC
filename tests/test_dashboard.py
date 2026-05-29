from detlab.dashboard import generate_dashboard
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
        "status": "stable",
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


def test_generate_dashboard():
    html = generate_dashboard([TEST_DETECTION])

    assert "<html>" in html
    assert "DetLab Security Analytics Dashboard" in html
    assert "execution: 1" in html
    assert "high: 1" in html
