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



def test_generate_analytics_keeps_weak_detection_identity_aligned_with_scores():
    strong_detection = Detection.model_validate(
        {
            "id": "DET-0002",
            "title": "A Strong Detection",
            "description": "Well-specified detection with metadata and tests.",
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
                    "EventID": 4688,
                    "CommandLine|contains": ["-enc", "FromBase64String"],
                },
                "condition": "selection",
            },
        }
    )
    weak_detection = Detection.model_validate(
        {
            "id": "DET-0003",
            "title": "Z Weak Detection",
            "description": "Minimal detection with weak matching.",
            "logsource": {
                "product": "windows",
                "service": "process_creation",
            },
            "attack": {
                "technique": "T1059.001",
                "tactic": "execution",
            },
            "severity": "low",
            "status": "experimental",
            "author": "Mell0wx",
            "references": [],
            "falsepositives": [],
            "tests": [
                {
                    "name": "Manual Test",
                    "source": "lab",
                    "test_id": "1",
                }
            ],
            "detection": {
                "selection": {
                    "CommandLine|contains": "powershell"
                },
                "condition": "selection",
            },
        }
    )

    analytics = generate_analytics([weak_detection, strong_detection])

    assert analytics["weak_detections"] == [
        {
            "id": "DET-0003",
            "title": "Z Weak Detection",
            "score": 57.8,
        }
    ]
