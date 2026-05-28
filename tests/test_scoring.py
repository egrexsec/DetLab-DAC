from detlab.models import Detection
from detlab.scoring import score_detection


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


def test_score_detection():
    result = score_detection(TEST_DETECTION)

    assert result["score"] >= 80
    assert result["severity"] == "high"
    assert result["status"] == "stable"



def test_score_has_recommendations_field():
    result = score_detection(TEST_DETECTION)

    assert "recommendations" in result
    assert isinstance(result["recommendations"], list)
