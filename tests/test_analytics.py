from detlab.analytics import generate_analytics
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


def test_generate_analytics():
    analytics = generate_analytics([TEST_DETECTION])

    assert analytics["total_detections"] == 1
    assert analytics["tactics"]["execution"] == 1
    assert analytics["techniques"]["T1059.001"] == 1
    assert analytics["platforms"]["windows"] == 1
    assert analytics["severity"]["high"] == 1
    assert analytics["status"]["stable"] == 1
    assert analytics["coverage_percent"] > 0
