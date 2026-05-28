from pydantic import ValidationError

from detlab.models import Detection


VALID_DETECTION = {
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


def test_valid_detection():
    detection = Detection.model_validate(VALID_DETECTION)

    assert detection.id == "DET-0001"


def test_invalid_attack_id():
    invalid = VALID_DETECTION.copy()
    invalid["attack"] = {
        "technique": "INVALID",
        "tactic": "execution",
    }

    try:
        Detection.model_validate(invalid)
        assert False
    except ValidationError:
        assert True


def test_missing_tests():
    invalid = VALID_DETECTION.copy()
    invalid["tests"] = []

    try:
        Detection.model_validate(invalid)
        assert False
    except ValidationError:
        assert True
