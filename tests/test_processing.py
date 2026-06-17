from detlab.processing import (
    UnsupportedConversionTargetError,
    convert_detection_content,
    inspect_detection_content,
)

SAMPLE_DETECTION_YAML = """id: DET-9002
title: Suspicious Encoded PowerShell
description: Detects PowerShell launched with encoded command arguments.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1059.001
  tactic: execution
severity: high
status: experimental
author: Mell0wx
references:
  - https://attack.mitre.org/techniques/T1059/001/
falsepositives:
  - Administrative scripts using encoded commands
tests:
  - name: Atomic Red Team T1059.001
    source: atomic-red-team
    test_id: "1"
detection:
  selection:
    EventID: 1
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
"""


def test_inspect_detection_content_returns_normalized_detection_and_score():
    result = inspect_detection_content(SAMPLE_DETECTION_YAML)

    assert result["valid"] is True
    assert result["errors"] == []
    assert result["detection"]["id"] == "DET-9002"
    assert result["score"]["overall_score"] > 0



def test_inspect_detection_content_returns_structured_errors_for_invalid_detection():
    result = inspect_detection_content("title: missing required fields")

    assert result["valid"] is False
    assert result["errors"]
    assert isinstance(result["errors"], list)



def test_convert_detection_content_returns_rendered_output_for_supported_target():
    result = convert_detection_content(SAMPLE_DETECTION_YAML, "sigma")

    assert result["valid"] is True
    assert result["target"] == "sigma"
    assert "title: Suspicious Encoded PowerShell" in result["content"]



def test_convert_detection_content_rejects_unsupported_target():
    try:
        convert_detection_content(SAMPLE_DETECTION_YAML, "bogus")
        assert False
    except UnsupportedConversionTargetError as exc:
        assert str(exc) == "Unsupported conversion target: bogus"



def test_inspect_detection_content_rejects_unsupported_condition_expressions():
    result = inspect_detection_content(SAMPLE_DETECTION_YAML.replace("condition: selection", "condition: selection or nonexistent"))

    assert result["valid"] is False
    assert any("detection.condition" in ".".join(map(str, error["loc"])) for error in result["errors"])



def test_convert_detection_content_rejects_unsafe_query_values():
    malicious = SAMPLE_DETECTION_YAML.replace("'-encodedcommand'", "'foo\\\" OR index=* OR \\\"bar'")

    splunk = convert_detection_content(malicious, "splunk")
    kql = convert_detection_content(malicious, "kql")
    eql = convert_detection_content(malicious, "eql")

    for result in (splunk, kql, eql):
        assert result["valid"] is False
        assert any(error["type"] == "unsafe_conversion_value" for error in result["errors"])



def test_inspect_detection_content_rejects_unsafe_selection_keys():
    malicious = SAMPLE_DETECTION_YAML.replace("CommandLine|contains:", "CommandLine) OR * OR (foo|contains:")

    result = inspect_detection_content(malicious)

    assert result["valid"] is False
    assert any("detection.selection" in ".".join(map(str, error["loc"])) for error in result["errors"])



def test_inspect_detection_content_rejects_nested_selection_values():
    malicious = SAMPLE_DETECTION_YAML.replace("EventID: 1", "EventID:\n      nested: 1")

    result = inspect_detection_content(malicious)

    assert result["valid"] is False
    assert any("detection.selection" in ".".join(map(str, error["loc"])) for error in result["errors"])
