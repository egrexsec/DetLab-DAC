from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from detlab.db.base import Base

if TYPE_CHECKING:
    from detlab.db.models.attack import DetectionAttackMapping
    from detlab.db.models.reference import DetectionReference
    from detlab.db.models.tag import DetectionTag


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    detection_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    author: Mapped[str] = mapped_column(String(255), nullable=False)
    logsource_product: Mapped[str] = mapped_column(String(255), nullable=False)
    logsource_service: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    attack_mappings: Mapped[list[DetectionAttackMapping]] = relationship(
        back_populates="detection",
        cascade="all, delete-orphan",
    )
    references: Mapped[list[DetectionReference]] = relationship(
        back_populates="detection",
        cascade="all, delete-orphan",
    )
    tags: Mapped[list[DetectionTag]] = relationship(
        back_populates="detection",
        cascade="all, delete-orphan",
    )
    logic_variants: Mapped[list[DetectionLogicVariant]] = relationship(
        back_populates="detection",
        cascade="all, delete-orphan",
    )


class DetectionLogicVariant(Base):
    __tablename__ = "detection_logic_variants"
    __table_args__ = (UniqueConstraint("detection_id", "language", name="uq_detection_logic_variant_language"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    detection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detections.id"), nullable=False)
    language: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    detection: Mapped[Detection] = relationship(back_populates="logic_variants")
