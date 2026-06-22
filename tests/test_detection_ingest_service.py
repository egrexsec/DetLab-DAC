from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, select

from detlab.db.base import Base
from detlab.db.models import (
    AttackTechnique,
    AttackTactic,
    Detection,
    DetectionAttackMapping,
    DetectionLogicVariant,
    DetectionReference,
    DetectionTag,
)
from detlab.db.session import build_session_factory
from detlab.services.detection_ingest_service import DetectionIngestService
from detlab.sources import DetectionSource, resolve_and_describe_detection_source

SAMPLE_MARKDOWN = """---
id: DET-3101
name: Encoded PowerShell
content_kind: hunt
status: validated
severity: high
author: mell0wx
domain:
  - endpoint
platforms:
  - windows
  - mde
logsource:
  product: mde
  service: advanced_hunting
attack:
  technique: T1059.001
  tactic: execution
attack_context:
  - technique: T1027
    tactic: defense-evasion
    name: Obfuscated Files or Information
    coverage: partial
    rationale: Encoded commands frequently overlap with obfuscation.
data_sources:
  - name: DeviceProcessEvents
    kind: process
    provider: mde
triage_steps:
  - step: Validate the affected user, host, and parent process.
    priority: high
investigation_steps:
  - step: Collect command-line history and nearby network activity.
    priority: high
references:
  - https://attack.mitre.org/techniques/T1059/001/
falsepositives:
  - Administrative automation using encoded commands.
tests:
  - name: Analyst validation
    source: markdown-curation
    test_id: encoded-powershell-v1
---

# Encoded PowerShell

This markdown knowledge entry captures PowerShell execution hunting guidance for encoded command usage.

## Query
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
```
"""


SAMPLE_YAML = """id: DET-4100
title: Suspicious Rundll32 Execution
description: Detects rundll32 being used with suspicious command-line patterns.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1218.011
  tactic: defense-evasion
severity: medium
status: production
author: mell0wx
domain:
  - endpoint
platforms:
  - windows
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
falsepositives:
  - Legitimate control panel applet launches
tests:
  - name: Analyst validation
    source: unit
    test_id: rundll32-1
detection:
  selection:
    EventID: 1
    Image|endswith: '\\\\rundll32.exe'
  condition: selection
"""


def _write_source(tmp_path: Path) -> Path:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "encoded-powershell.md").write_text(SAMPLE_MARKDOWN, encoding="utf-8")
    (source_dir / "rundll32.yml").write_text(SAMPLE_YAML, encoding="utf-8")
    return source_dir


def test_detection_ingest_service_imports_source_detections_with_mappings_and_metadata_tags(tmp_path: Path):
    source_dir = _write_source(tmp_path)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = build_session_factory(engine)
    service = DetectionIngestService(session_factory)

    summary = service.ingest_source(str(source_dir))

    assert summary == {
        "source_path": str(source_dir),
        "created": 2,
        "updated": 0,
        "total": 2,
    }

    with session_factory() as session:
        detections = session.scalars(select(Detection).order_by(Detection.detection_id)).all()
        assert [item.detection_id for item in detections] == ["DET-3101", "DET-4100"]

        markdown_detection = session.scalar(select(Detection).where(Detection.detection_id == "DET-3101"))
        assert markdown_detection is not None
        assert markdown_detection.slug == "encoded-powershell"
        assert markdown_detection.logsource_product == "mde"

        markdown_tags = session.scalars(
            select(DetectionTag.tag)
            .join(Detection, Detection.id == DetectionTag.detection_id)
            .where(Detection.detection_id == "DET-3101")
            .order_by(DetectionTag.tag)
        ).all()
        assert "domain:endpoint" in markdown_tags
        assert "platform:mde" in markdown_tags
        assert "platform:windows" in markdown_tags
        assert "source_format:markdown" in markdown_tags
        assert "normalized_from:markdown_frontmatter" in markdown_tags
        assert "source_path:encoded-powershell.md" in markdown_tags

        reference_urls = session.scalars(
            select(DetectionReference.url)
            .join(Detection, Detection.id == DetectionReference.detection_id)
            .where(Detection.detection_id == "DET-3101")
        ).all()
        assert reference_urls == ["https://attack.mitre.org/techniques/T1059/001/"]

        techniques = session.scalars(select(AttackTechnique).order_by(AttackTechnique.attack_id)).all()
        assert [item.attack_id for item in techniques] == ["T1027", "T1059.001", "T1218.011"]

        tactics = session.scalars(select(AttackTactic).order_by(AttackTactic.short_name)).all()
        assert [item.short_name for item in tactics] == ["defense-evasion", "execution"]

        mappings = session.scalars(
            select(DetectionAttackMapping)
            .join(Detection, Detection.id == DetectionAttackMapping.detection_id)
            .where(Detection.detection_id == "DET-3101")
        ).all()
        assert len(mappings) == 2

        markdown_variants = session.scalars(
            select(DetectionLogicVariant)
            .join(Detection, Detection.id == DetectionLogicVariant.detection_id)
            .where(Detection.detection_id == "DET-3101")
            .order_by(DetectionLogicVariant.language)
        ).all()
        assert [variant.language for variant in markdown_variants] == ["eql", "kql", "markdown", "sigma", "splunk"]
        assert next(variant for variant in markdown_variants if variant.language == "markdown").is_primary is True
        assert next(variant for variant in markdown_variants if variant.language == "markdown").content

        yaml_variants = session.scalars(
            select(DetectionLogicVariant)
            .join(Detection, Detection.id == DetectionLogicVariant.detection_id)
            .where(Detection.detection_id == "DET-4100")
            .order_by(DetectionLogicVariant.language)
        ).all()
        assert [variant.language for variant in yaml_variants] == ["eql", "kql", "sigma", "splunk", "yaml"]
        assert next(variant for variant in yaml_variants if variant.language == "yaml").is_primary is True
        assert "title: Suspicious Rundll32 Execution" in next(
            variant for variant in yaml_variants if variant.language == "yaml"
        ).content


def test_detection_ingest_service_updates_existing_detection_in_place(tmp_path: Path):
    source_dir = _write_source(tmp_path)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = build_session_factory(engine)
    service = DetectionIngestService(session_factory)

    first_summary = service.ingest_source(str(source_dir))
    assert first_summary["created"] == 2

    updated_markdown = SAMPLE_MARKDOWN.replace("status: validated", "status: production").replace(
        "This markdown knowledge entry captures PowerShell execution hunting guidance for encoded command usage.",
        "Updated description for imported markdown detection.",
    )
    (source_dir / "encoded-powershell.md").write_text(updated_markdown, encoding="utf-8")

    second_summary = service.ingest_source(str(source_dir))

    assert second_summary == {
        "source_path": str(source_dir),
        "created": 0,
        "updated": 2,
        "total": 2,
    }

    with session_factory() as session:
        detection = session.scalar(select(Detection).where(Detection.detection_id == "DET-3101"))
        assert detection is not None
        assert detection.status == "production"
        assert detection.description == "Updated description for imported markdown detection."


def test_detection_ingest_service_deduplicates_attack_mappings_for_repeated_techniques(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    duplicate_mapping_yaml = """id: DET-5000
title: Duplicate Mapping Detection
description: Detects duplicate ATT&CK mapping input without creating duplicate DB rows.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1059.001
  tactic: execution
severity: high
status: production
author: mell0wx
tests:
  - name: Analyst validation
    source: unit
    test_id: duplicate-mapping
detection:
  selection:
    EventID: 1
  condition: selection
attack_context:
  - technique: T1059.001
    tactic: execution
    coverage: direct
  - technique: T1059.001
    tactic: execution
    coverage: related
"""
    (source_dir / "duplicate.yml").write_text(duplicate_mapping_yaml, encoding="utf-8")

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = build_session_factory(engine)

    summary = DetectionIngestService(session_factory).ingest_source(str(source_dir))

    assert summary["created"] == 1
    with session_factory() as session:
        mappings = session.scalars(select(DetectionAttackMapping)).all()
        assert len(mappings) == 1


def test_detection_ingest_service_generates_unique_slugs_for_duplicate_titles(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    duplicate_title_template = """id: {detection_id}
title: Shared Detection Title
description: Two detections intentionally share the same title.
logsource:
  product: windows
  service: sysmon
attack:
  technique: {technique}
  tactic: execution
severity: medium
status: production
author: mell0wx
tests:
  - name: Analyst validation
    source: unit
    test_id: {detection_id}
detection:
  selection:
    EventID: 1
  condition: selection
"""
    (source_dir / "one.yml").write_text(
        duplicate_title_template.format(detection_id="DET-6000", technique="T1059.001"),
        encoding="utf-8",
    )
    (source_dir / "two.yml").write_text(
        duplicate_title_template.format(detection_id="DET-6001", technique="T1218.011"),
        encoding="utf-8",
    )

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = build_session_factory(engine)

    summary = DetectionIngestService(session_factory).ingest_source(str(source_dir))

    assert summary["created"] == 2
    with session_factory() as session:
        slugs = session.scalars(select(Detection.slug).order_by(Detection.detection_id)).all()
        assert slugs == ["shared-detection-title", "shared-detection-title-det-6001"]


def test_detection_ingest_service_does_not_overwrite_shared_primary_attack_technique_names(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    shared_technique_template = """id: {detection_id}
title: {title}
description: Shared technique import.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1059.001
  tactic: execution
severity: high
status: production
author: mell0wx
tests:
  - name: Analyst validation
    source: unit
    test_id: {detection_id}
detection:
  selection:
    EventID: 1
  condition: selection
"""
    (source_dir / "one.yml").write_text(
        shared_technique_template.format(detection_id="DET-7000", title="First Title"),
        encoding="utf-8",
    )
    (source_dir / "two.yml").write_text(
        shared_technique_template.format(detection_id="DET-7001", title="Second Title"),
        encoding="utf-8",
    )

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = build_session_factory(engine)

    DetectionIngestService(session_factory).ingest_source(str(source_dir))

    with session_factory() as session:
        technique = session.scalar(select(AttackTechnique).where(AttackTechnique.attack_id == "T1059.001"))
        assert technique is not None
        assert technique.name == "T1059.001"


def test_detection_ingest_service_does_not_overwrite_existing_attack_technique_tactic(tmp_path: Path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    conflicting_tactic_template = """id: {detection_id}
title: {title}
description: Conflicting tactic import.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1110
  tactic: {tactic}
severity: high
status: production
author: mell0wx
tests:
  - name: Analyst validation
    source: unit
    test_id: {detection_id}
detection:
  selection:
    EventID: 1
  condition: selection
"""
    (source_dir / "one.yml").write_text(
        conflicting_tactic_template.format(
            detection_id="DET-7100",
            title="Credential Access Detection",
            tactic="credential-access",
        ),
        encoding="utf-8",
    )
    (source_dir / "two.yml").write_text(
        conflicting_tactic_template.format(
            detection_id="DET-7101",
            title="Initial Access Detection",
            tactic="initial-access",
        ),
        encoding="utf-8",
    )

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = build_session_factory(engine)

    DetectionIngestService(session_factory).ingest_source(str(source_dir))

    with session_factory() as session:
        technique = session.scalar(select(AttackTechnique).where(AttackTechnique.attack_id == "T1110"))
        assert technique is not None
        assert technique.tactic.short_name == "credential-access"


def test_resolve_and_describe_detection_source_syncs_github_source_once(monkeypatch, tmp_path: Path):
    source = DetectionSource(mode="github", repo_url="https://github.com/example/project.git", ref="main", subdir="detections")
    resolved_dir = tmp_path / "synced"
    resolved_dir.mkdir()
    calls: list[str] = []

    def fake_sync(*args, **kwargs):
        calls.append("sync")
        return resolved_dir

    monkeypatch.setattr("detlab.sources.sync_github_source", fake_sync)
    monkeypatch.setattr("detlab.sources.parse_github_source_spec", lambda spec: source)

    resolved_path, status = resolve_and_describe_detection_source("github://example/project/detections?ref=main")

    assert resolved_path == resolved_dir
    assert status["resolved_path"] == str(resolved_dir.resolve())
    assert calls == ["sync"]
