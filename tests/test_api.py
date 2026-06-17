import importlib

from fastapi.testclient import TestClient

from detlab import api as api_module

client = TestClient(api_module.app)

SAMPLE_DETECTION_YAML = """id: DET-9001
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


def test_health_endpoint():
    response = client.get('/health')

    assert response.status_code == 200
    assert response.json()['status'] == 'ok'



def test_dashboard_endpoint_exposes_workbench_sections():
    response = client.get('/dashboard')

    assert response.status_code == 200
    body = response.json()
    assert 'summary' in body
    assert 'coverage' in body
    assert 'scoring' in body
    assert 'packs' in body
    assert 'review_queue' in body
    assert body['summary']['total_detections'] >= 1



def test_dashboard_endpoint_exposes_actionable_review_queue():
    response = client.get('/dashboard')

    assert response.status_code == 200
    body = response.json()

    assert body['review_queue']['high_risk_gaps']
    first_gap = body['review_queue']['high_risk_gaps'][0]
    assert first_gap['tactic']
    assert first_gap['priority'] == 'high'
    assert first_gap['recommended_pack']
    assert first_gap['recommended_action']



def test_docs_use_root_path_when_configured(monkeypatch):
    monkeypatch.setenv('DETLAB_ROOT_PATH', '/api')
    reloaded = importlib.reload(api_module)
    try:
        configured_client = TestClient(reloaded.app)
        response = configured_client.get('/docs')

        assert response.status_code == 200
        assert "url: '/api/openapi.json'" in response.text
        assert "window.location.origin + '/api/docs/oauth2-redirect'" in response.text
    finally:
        monkeypatch.delenv('DETLAB_ROOT_PATH', raising=False)
        importlib.reload(api_module)



def test_inspect_detection_endpoint_returns_validation_and_score():
    response = client.post('/detections/inspect', json={'content': SAMPLE_DETECTION_YAML})

    assert response.status_code == 200
    body = response.json()
    assert body['valid'] is True
    assert body['errors'] == []
    assert body['detection']['id'] == 'DET-9001'
    assert body['score']['overall_score'] > 0
    assert isinstance(body['score']['recommendations'], list)



def test_inspect_detection_endpoint_returns_structured_errors_for_invalid_payload():
    response = client.post('/detections/inspect', json={'content': 'title: missing required fields'})

    assert response.status_code == 422
    body = response.json()
    assert body['valid'] is False
    assert body['errors']



def test_convert_detection_endpoint_returns_backend_specific_content():
    response = client.post(
        '/detections/convert',
        json={'content': SAMPLE_DETECTION_YAML, 'target': 'splunk'},
    )

    assert response.status_code == 200
    body = response.json()
    assert body['target'] == 'splunk'
    assert 'search' in body['content']
    assert body['valid'] is True



def test_convert_detection_endpoint_rejects_unsupported_targets():
    response = client.post(
        '/detections/convert',
        json={'content': SAMPLE_DETECTION_YAML, 'target': 'bogus'},
    )

    assert response.status_code == 400
    assert response.json()['detail'] == 'Unsupported conversion target: bogus'



def test_inspect_detection_endpoint_rejects_oversized_payloads():
    response = client.post('/detections/inspect', json={'content': 'a' * 30000})

    assert response.status_code == 413
    assert response.json()['detail'] == 'Detection request body exceeds 25000 bytes'



def test_convert_detection_endpoint_rejects_unsafe_query_values():
    malicious = SAMPLE_DETECTION_YAML.replace("'-encodedcommand'", "'foo\\\" OR index=* OR \\\"bar'")
    response = client.post('/detections/convert', json={'content': malicious, 'target': 'splunk'})

    assert response.status_code == 422
    body = response.json()
    assert body['valid'] is False
    assert any(error['type'] == 'unsafe_conversion_value' for error in body['errors'])



def test_inspect_detection_endpoint_rejects_invalid_content_length_header():
    response = client.post(
        '/detections/inspect',
        content='{"content":"id: DET-9001"}',
        headers={'content-type': 'application/json', 'content-length': 'abc'},
    )

    assert response.status_code == 400
    assert response.json()['detail'] == 'Invalid Content-Length header'



def test_inspect_detection_endpoint_rejects_unsafe_selection_keys():
    malicious = SAMPLE_DETECTION_YAML.replace("CommandLine|contains:", "CommandLine) OR * OR (foo|contains:")
    response = client.post('/detections/inspect', json={'content': malicious})

    assert response.status_code == 422
    body = response.json()
    assert body['valid'] is False
    assert body['errors']



def test_inspect_detection_endpoint_rejects_nested_selection_values():
    malicious = SAMPLE_DETECTION_YAML.replace("EventID: 1", "EventID:\n      nested: 1")
    response = client.post('/detections/inspect', json={'content': malicious})

    assert response.status_code == 422
    body = response.json()
    assert body['valid'] is False
    assert body['errors']
