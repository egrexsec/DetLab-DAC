import importlib

from fastapi.testclient import TestClient

from detlab import api as api_module

client = TestClient(api_module.app)


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
    assert body['summary']['total_detections'] >= 1



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
