import importlib

import yaml
from fastapi.testclient import TestClient

from detlab import api as api_module
from detlab.kql import export_kql_detection
from detlab.models import Detection

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

SAMPLE_DETECTION_KQL = export_kql_detection(Detection.model_validate(yaml.safe_load(SAMPLE_DETECTION_YAML)))


def test_health_endpoint():
    response = client.get('/health')

    assert response.status_code == 200
    assert response.json()['status'] == 'ok'



def test_dashboard_endpoint_exposes_workbench_sections():
    response = client.get('/dashboard')

    assert response.status_code == 200
    body = response.json()
    assert 'summary' in body
    assert 'source' in body
    assert 'coverage' in body
    assert 'scoring' in body
    assert 'review_queue' in body
    assert body['summary']['total_detections'] >= 1



def test_source_endpoint_returns_local_detection_directory_metadata():
    response = client.get('/source')

    assert response.status_code == 200
    body = response.json()
    assert body['mode'] == 'local'
    assert body['subdir'] == 'detections'
    assert body['resolved_path']



def test_domain_schema_endpoint_exposes_detection_schema():
    response = client.get('/schema/domain')

    assert response.status_code == 200
    body = response.json()
    assert body['primary_entity'] == 'Detection'
    assert 'Detection' in body['entities']
    assert 'RelatedDetection' in body['entities']



def test_detection_catalog_endpoint_returns_detection_first_entries():
    response = client.get('/detections/catalog')

    assert response.status_code == 200
    body = response.json()
    assert body['total'] >= 1
    assert any('investigation_readiness_score' in item for item in body['detections'])



def test_detection_workspace_endpoint_returns_visual_investigation_payload():
    response = client.get('/detections/DET-0001/workspace')

    assert response.status_code == 200
    body = response.json()
    assert body['detection']['id'] == 'DET-0001'
    assert 'overview' in body
    assert 'heat_map' in body
    assert 'relationship_graph' in body
    assert body['heat_map']['direct'][0]['technique'] == 'T1059.001'
    assert body['source_format'] == 'yaml'
    assert body['normalized_from'] == 'canonical_yaml'
    assert body['canonical_model_version']



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



def test_convert_detection_endpoint_supports_kql_authored_input():
    response = client.post(
        '/detections/convert',
        json={'content': SAMPLE_DETECTION_KQL, 'target': 'sigma'},
    )

    assert response.status_code == 200
    body = response.json()
    assert body['target'] == 'sigma'
    assert body['valid'] is True
    assert 'title: Suspicious Encoded PowerShell' in body['content']
    assert body['source_format'] == 'kql'
    assert body['normalized_from'] == 'kql_export'
    assert body['canonical_model_version']



def test_detection_templates_endpoint_returns_generic_authoring_templates():
    response = client.get('/detections/templates')

    assert response.status_code == 200
    body = response.json()
    assert body['default_format'] == 'yaml'
    assert body['canonical_model_version']
    assert 'yaml' in body['templates']
    assert 'markdown' in body['templates']
    assert 'sigma' in body['templates']
    assert 'splunk' in body['templates']
    assert 'kql' in body['templates']
    assert 'eql' in body['templates']
    assert 'Detects suspicious PowerShell' in body['templates']['yaml']['content']



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
