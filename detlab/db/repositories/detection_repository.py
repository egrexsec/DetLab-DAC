from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from detlab.db.models import AttackTechnique, Detection, DetectionAttackMapping


def _detection_detail_load_options():
    return (
        selectinload(Detection.tags),
        selectinload(Detection.references),
        selectinload(Detection.attack_mappings)
        .selectinload(DetectionAttackMapping.technique)
        .selectinload(AttackTechnique.tactic),
    )


class DetectionRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_detection(self, **detection_fields: object) -> Detection:
        detection = Detection(**detection_fields)
        self.session.add(detection)
        self.session.commit()
        return self.get_by_slug_and_status(detection.slug, detection.status) or detection

    def list_by_status(self, status: str) -> Sequence[Detection]:
        statement = (
            select(Detection)
            .options(*_detection_detail_load_options())
            .where(Detection.status == status)
            .order_by(Detection.slug.asc())
        )
        return self.session.scalars(statement).all()

    def get_by_slug_and_status(self, slug: str, status: str) -> Detection | None:
        statement = (
            select(Detection)
            .options(*_detection_detail_load_options())
            .where(Detection.slug == slug, Detection.status == status)
        )
        return self.session.scalars(statement).first()
