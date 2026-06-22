from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from detlab.db.base import Base

if TYPE_CHECKING:
    from detlab.db.models.detection import Detection


class AttackTactic(Base):
    __tablename__ = "attack_tactics"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    attack_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    short_name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    techniques: Mapped[list[AttackTechnique]] = relationship(
        back_populates="tactic",
        cascade="all, delete-orphan",
    )


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    attack_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_tactics.id"), nullable=False)

    tactic: Mapped[AttackTactic] = relationship(back_populates="techniques")
    detection_mappings: Mapped[list[DetectionAttackMapping]] = relationship(
        back_populates="technique",
        cascade="all, delete-orphan",
    )


class DetectionAttackMapping(Base):
    __tablename__ = "detection_attack_mappings"
    __table_args__ = (UniqueConstraint("detection_id", "technique_id", name="uq_detection_technique_mapping"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    detection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detections.id"), nullable=False)
    technique_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("attack_techniques.id"), nullable=False)
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    detection: Mapped[Detection] = relationship(back_populates="attack_mappings")
    technique: Mapped[AttackTechnique] = relationship(back_populates="detection_mappings")
