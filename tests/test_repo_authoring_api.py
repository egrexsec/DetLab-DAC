from pathlib import Path

from fastapi.testclient import TestClient

from detlab import api as api_module

client = TestClient(api_module.app)


HUNT_MARKDOWN = """---
id: DET-4101
content_kind: hunt
name: Rare IAM User Hunt
description: Hunt for unusual IAM user creation patterns.
severity: medium
status: draft
author: DetLab
references:
  - https://example.com/hunt
attack:
  technique: T1136.003
  tactic: persistence
query:
  language: kusto
  text: |
    AuditLogs
    | where OperationName == \"Add user\"
---

# Rare IAM User Hunt

## Hypothesis
- Adversaries may create IAM users outside approved workflows.

## Investigation Steps
- Review actor context and source IPs.
"""


LEARNING_MARKDOWN = """---
id: DET-4102
content_kind: learning_path
name: IAM Foundations Learning Path
description: Baseline IAM knowledge path for analysts.
severity: medium
status: validated
author: DetLab
references:
  - https://example.com/learn
attack:
  technique: T1078
  tactic: initial-access
query:
  language: markdown
  text: Study IAM policies and trust boundaries.
---

# IAM Foundations Learning Path

## Modules
- IAM policy evaluation
- SCPs and delegated administration
"""


def _init_git_repo(repo_root: Path) -> None:
    (repo_root / 'detections').mkdir(parents=True, exist_ok=True)
    (repo_root / 'knowledge').mkdir(parents=True, exist_ok=True)
    import subprocess

    subprocess.run(['git', 'init'], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run(['git', 'checkout', '-b', 'main'], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run(['git', 'config', 'user.name', 'DetLab Tests'], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run(['git', 'config', 'user.email', 'detlab-tests@example.com'], cwd=repo_root, check=True, capture_output=True, text=True)


def test_content_indexes_endpoint_groups_knowledge_entries(tmp_path, monkeypatch):
    knowledge_root = tmp_path / 'knowledge'
    hunt_path = knowledge_root / 'threat-hunts' / 'aws' / 'rare-iam-user-hunt.md'
    learning_path = knowledge_root / 'learning-paths' / 'aws' / 'iam-foundations.md'
    hunt_path.parent.mkdir(parents=True, exist_ok=True)
    learning_path.parent.mkdir(parents=True, exist_ok=True)
    hunt_path.write_text(HUNT_MARKDOWN, encoding='utf-8')
    learning_path.write_text(LEARNING_MARKDOWN, encoding='utf-8')

    response = client.get('/content/indexes', params={'path': str(knowledge_root)})

    assert response.status_code == 200
    body = response.json()
    assert body['total'] == 2
    assert body['indexes']['hunts']['count'] == 1
    assert body['indexes']['hunts']['items'][0]['path'] == 'threat-hunts/aws/rare-iam-user-hunt.md'
    assert body['indexes']['learning_paths']['count'] == 1
    assert body['indexes']['learning_paths']['items'][0]['content_kind'] == 'learning_path'
    assert body['indexes']['investigations']['count'] == 0
    assert body['indexes']['forensics']['count'] == 0


def test_repo_status_endpoint_returns_branch_and_changed_files(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    _init_git_repo(repo_root)
    tracked_file = repo_root / 'knowledge' / 'threat-hunts' / 'draft.md'
    tracked_file.parent.mkdir(parents=True, exist_ok=True)
    tracked_file.write_text(HUNT_MARKDOWN, encoding='utf-8')

    monkeypatch.setattr(api_module, 'REPO_ROOT', repo_root)

    save_response = client.post('/detections/save', json={'path': 'knowledge/threat-hunts/draft.md', 'content': HUNT_MARKDOWN.replace('DET-4101', 'DET-4111')})
    assert save_response.status_code == 200

    response = client.get('/repo/status')

    assert response.status_code == 200
    body = response.json()
    assert body['branch'] == 'main'
    assert body['clean'] is False
    assert any(item['path'] == 'knowledge/threat-hunts/draft.md' for item in body['changed_files'])


def test_repo_diff_endpoint_returns_unified_diff_for_saved_file(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    _init_git_repo(repo_root)
    tracked_file = repo_root / 'knowledge' / 'threat-hunts' / 'hunt.md'
    tracked_file.parent.mkdir(parents=True, exist_ok=True)
    tracked_file.write_text(HUNT_MARKDOWN, encoding='utf-8')

    import subprocess

    subprocess.run(['git', 'add', '.'], cwd=repo_root, check=True, capture_output=True, text=True)
    subprocess.run(['git', 'commit', '-m', 'Initial knowledge content'], cwd=repo_root, check=True, capture_output=True, text=True)

    monkeypatch.setattr(api_module, 'REPO_ROOT', repo_root)

    save_response = client.post('/detections/save', json={'path': 'knowledge/threat-hunts/hunt.md', 'content': HUNT_MARKDOWN.replace('Rare IAM User Hunt', 'Rare IAM User Hunt Updated')})
    assert save_response.status_code == 200

    response = client.get('/repo/diff', params={'path': 'knowledge/threat-hunts/hunt.md'})

    assert response.status_code == 200
    body = response.json()
    assert body['path'] == 'knowledge/threat-hunts/hunt.md'
    assert 'Rare IAM User Hunt Updated' in body['diff']
    assert '--- a/knowledge/threat-hunts/hunt.md' in body['diff']


def test_repo_content_endpoint_returns_saved_artifact_for_editing(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    _init_git_repo(repo_root)

    artifact_path = repo_root / 'knowledge' / 'threat-hunts' / 'aws' / 'rare-iam-user-hunt.md'
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(HUNT_MARKDOWN, encoding='utf-8')

    monkeypatch.setattr(api_module, 'REPO_ROOT', repo_root)

    response = client.get('/repo/content', params={'path': 'knowledge/threat-hunts/aws/rare-iam-user-hunt.md'})

    assert response.status_code == 200
    body = response.json()
    assert body['path'] == 'knowledge/threat-hunts/aws/rare-iam-user-hunt.md'
    assert body['content'] == HUNT_MARKDOWN
    assert body['content_kind'] == 'hunt'
    assert body['name'] == 'Rare IAM User Hunt'


def test_repo_commit_endpoint_creates_commit_and_returns_metadata(tmp_path, monkeypatch):
    repo_root = tmp_path / 'repo'
    repo_root.mkdir()
    _init_git_repo(repo_root)

    monkeypatch.setattr(api_module, 'REPO_ROOT', repo_root)

    save_response = client.post('/detections/save', json={'path': 'knowledge/threat-hunts/new-hunt.md', 'content': HUNT_MARKDOWN})
    assert save_response.status_code == 200

    response = client.post('/repo/commit', json={'message': 'Add threat hunt artifact'})

    assert response.status_code == 200
    body = response.json()
    assert body['committed'] is True
    assert body['branch'] == 'main'
    assert body['message'] == 'Add threat hunt artifact'
    assert body['commit']
    assert any(item['path'] == 'knowledge/threat-hunts/new-hunt.md' for item in body['changed_files'])

    status_response = client.get('/repo/status')
    assert status_response.status_code == 200
    assert status_response.json()['clean'] is True
