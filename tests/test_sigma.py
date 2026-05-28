from detlab.sigma import sigma_rule_to_detection


SIGMA_RULE = {
    "title": "Suspicious PowerShell Execution",
    "id": "sigma-001",
    "description": "Detects suspicious encoded PowerShell execution.",
    "status": "experimental",
    "author": "Sigma Community",
    "references": [
        "https://attack.mitre.org/techniques/T1059/001/"
    ],
    "logsource": {
        "product": "windows",
        "service": "process_creation",
    },
    "detection": {
        "selection": {
            "CommandLine|contains": "-enc"
        },
        "condition": "selection",
    },
    "level": "high",
    "tags": [
        "attack.execution",
        "attack.t1059.001",
    ],
}


def test_sigma_conversion():
    detection = sigma_rule_to_detection(SIGMA_RULE, "DET-1000")

    assert detection["id"] == "DET-1000"
    assert detection["attack"]["technique"] == "T1059.001"
    assert detection["severity"] == "high"
    assert detection["status"] == "experimental"
    assert detection["logsource"]["product"] == "windows"


def test_sigma_conversion_generates_tests():
    detection = sigma_rule_to_detection(SIGMA_RULE, "DET-1001")

    assert len(detection["tests"]) == 1
    assert detection["tests"][0]["source"] == "sigma"
