from pathlib import Path

import pytest

from detlab.sources import (
    DetectionSource,
    DetectionSourceError,
    describe_detection_source,
    parse_github_source_spec,
    resolve_detection_dir,
)


def test_parse_github_source_spec_extracts_repo_ref_and_subdir():
    source = parse_github_source_spec('github://mell0wx/detlab-content/library/detections?ref=main')

    assert source.mode == 'github'
    assert source.repo_url == 'https://github.com/mell0wx/detlab-content.git'
    assert source.ref == 'main'
    assert source.subdir == 'library/detections'



def test_parse_github_source_spec_rejects_incomplete_spec():
    with pytest.raises(DetectionSourceError):
        parse_github_source_spec('github://mell0wx/detlab-content')



def test_resolve_detection_dir_prefers_existing_local_path(tmp_path: Path):
    detection_dir = tmp_path / 'detections'
    detection_dir.mkdir()

    assert resolve_detection_dir(detection_dir) == detection_dir



def test_resolve_detection_dir_uses_environment_backed_repo(monkeypatch, tmp_path: Path):
    synced_dir = tmp_path / 'cache' / 'repo-main' / 'remote-detections'
    synced_dir.mkdir(parents=True)

    source = DetectionSource(
        mode='github',
        repo_url='https://github.com/mell0wx/detlab-content.git',
        ref='main',
        subdir='remote-detections',
    )

    monkeypatch.setenv('DETLAB_SOURCE_REPO', 'mell0wx/detlab-content')
    monkeypatch.setenv('DETLAB_SOURCE_REF', 'main')
    monkeypatch.setenv('DETLAB_SOURCE_SUBDIR', 'remote-detections')
    monkeypatch.setattr('detlab.sources.sync_github_source', lambda *_args, **_kwargs: synced_dir)

    resolved = resolve_detection_dir('detections', cache_root=tmp_path / 'cache')
    described = describe_detection_source('detections')

    assert resolved == synced_dir
    assert described['mode'] == 'github'
    assert described['repo_url'] == source.repo_url
    assert described['subdir'] == 'remote-detections'
    assert described['synced'] is True
