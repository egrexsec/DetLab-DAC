from __future__ import annotations

import re
from dataclasses import dataclass

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from detlab.db.models import (
    AttackTactic,
    AttackTechnique,
    Detection,
    DetectionAttackMapping,
    DetectionLogicVariant,
    DetectionReference,
    DetectionTag,
)
from detlab.domain import load_detections
from detlab.eql import export_eql_detection
from detlab.kql import export_kql_detection
from detlab.models import AttackContext
from detlab.processing import detection_metadata_tags
from detlab.sigma_export import export_sigma_detection
from detlab.sources import resolve_and_describe_detection_source
from detlab.splunk import export_splunk_detection


@dataclass(frozen=True, slots=True)
class DetectionIngestSummary:
    source_path: str
    created: int
    updated: int
    total: int

    def as_dict(self) -> dict[str, int | str]:
        return {
            "source_path": self.source_path,
            "created": self.created,
            "updated": self.updated,
            "total": self.total,
        }


class DetectionIngestService:
    def __init__(self, session_factory: sessionmaker):
        self.session_factory = session_factory

    def ingest_source(self, path: str = "detections") -> dict[str, int | str]:
        resolved_path, _ = resolve_and_describe_detection_source(path)
        detections = load_detections(str(resolved_path))

        created = 0
        updated = 0
        with self.session_factory() as session:
            for detection in detections:
                existing = session.scalar(select(Detection).where(Detection.detection_id == detection.id))
                slug = self._resolve_unique_slug(session, detection.id, detection.name or detection.title)
                if existing is None:
                    existing = Detection(
                        detection_id=detection.id,
                        slug=slug,
                        title=detection.title,
                        description=detection.description,
                        severity=detection.severity,
                        status=detection.status,
                        author=detection.author,
                        logsource_product=detection.logsource.product,
                        logsource_service=detection.logsource.service,
                    )
                    session.add(existing)
                    session.flush()
                    created += 1
                else:
                    updated += 1
                    existing.slug = slug
                    existing.title = detection.title
                    existing.description = detection.description
                    existing.severity = detection.severity
                    existing.status = detection.status
                    existing.author = detection.author
                    existing.logsource_product = detection.logsource.product
                    existing.logsource_service = detection.logsource.service

                self._replace_detection_relationships(session, existing, detection)

            session.commit()

        return DetectionIngestSummary(
            source_path=str(resolved_path),
            created=created,
            updated=updated,
            total=len(detections),
        ).as_dict()

    def _replace_detection_relationships(self, session: Session, record: Detection, detection) -> None:
        record.references.clear()
        record.tags.clear()
        record.attack_mappings.clear()
        record.logic_variants.clear()
        session.flush()

        reference_urls = [url for url in dict.fromkeys(detection.references) if url.startswith(("http://", "https://"))]
        record.references = [DetectionReference(url=url) for url in reference_urls]
        record.tags = [DetectionTag(tag=tag) for tag in detection_metadata_tags(detection)]
        record.logic_variants = [
            DetectionLogicVariant(language=language, content=content, is_primary=is_primary)
            for language, content, is_primary in _logic_variants_for_detection(detection)
        ]

        attack_entries = [_primary_attack_context(detection)] + list(detection.attack_context)
        mappings: list[DetectionAttackMapping] = []
        seen_techniques: set[str] = set()
        for index, context in enumerate(attack_entries):
            technique = self._get_or_create_attack_technique(session, context)
            if technique.attack_id in seen_techniques:
                continue
            seen_techniques.add(technique.attack_id)
            mappings.append(
                DetectionAttackMapping(
                    technique_id=technique.id,
                    role="primary" if index == 0 else context.coverage,
                    rationale=context.rationale,
                )
            )
        record.attack_mappings = mappings

    def _resolve_unique_slug(self, session: Session, detection_id: str, slug_source: str) -> str:
        base_slug = _slugify(slug_source, fallback=detection_id)
        existing = session.scalar(select(Detection).where(Detection.slug == base_slug))
        if existing is None or existing.detection_id == detection_id:
            return base_slug
        return f"{base_slug}-{detection_id.lower()}"

    def _get_or_create_attack_technique(self, session: Session, context: AttackContext) -> AttackTechnique:
        with session.no_autoflush:
            technique = session.scalar(select(AttackTechnique).where(AttackTechnique.attack_id == context.technique))
            if technique is not None:
                if context.name and technique.name == technique.attack_id:
                    technique.name = context.name
                return technique

            tactic = self._get_or_create_attack_tactic(session, context.tactic or "unknown")
            technique = AttackTechnique(
                attack_id=context.technique,
                name=context.name or context.technique,
                tactic=tactic,
            )
            session.add(technique)
            session.flush()
            return technique

    def _get_or_create_attack_tactic(self, session: Session, tactic_short_name: str) -> AttackTactic:
        with session.no_autoflush:
            tactic = session.scalar(select(AttackTactic).where(AttackTactic.short_name == tactic_short_name))
            if tactic is not None:
                return tactic

            tactic = AttackTactic(
                attack_id=tactic_short_name,
                short_name=tactic_short_name,
                name=_display_name(tactic_short_name),
            )
            session.add(tactic)
            session.flush()
            return tactic


def _primary_attack_context(detection) -> AttackContext:
    return AttackContext(
        technique=detection.attack.technique,
        tactic=detection.attack.tactic,
        name=None,
        coverage="direct",
        rationale="Primary ATT&CK mapping declared by the detection.",
    )


def _logic_variants_for_detection(detection) -> list[tuple[str, str, bool]]:
    source_format = str(detection.detection.selection.get("SourceFormat") or "yaml")
    primary_content = _render_primary_variant(detection, source_format)
    renderable = detection.model_copy(deep=True)
    renderable.detection.selection.pop("SourcePath", None)
    renderable.detection.selection.pop("SourceFormat", None)
    renderable.detection.selection.pop("NormalizedFrom", None)
    return [
        (source_format, primary_content, True),
        ("sigma", export_sigma_detection(renderable), False),
        ("splunk", export_splunk_detection(renderable), False),
        ("kql", export_kql_detection(renderable), False),
        ("eql", export_eql_detection(renderable), False),
    ]


def _render_primary_variant(detection, source_format: str) -> str:
    serialized = detection.model_dump(exclude_none=True)
    if source_format == "markdown":
        frontmatter = dict(serialized)
        description = frontmatter.pop("description", "")
        return (
            "---\n"
            f"{yaml.safe_dump(frontmatter, sort_keys=False).strip()}\n"
            "---\n\n"
            f"# {detection.title}\n\n"
            f"{description}\n"
        )
    return yaml.safe_dump(serialized, sort_keys=False)


def _slugify(value: str, *, fallback: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or fallback.lower()


def _display_name(short_name: str) -> str:
    return short_name.replace("-", " ").title()
