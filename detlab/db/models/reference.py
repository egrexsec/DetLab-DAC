from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from detlab.db.base import Base

if TYPE_CHECKING:
    from detlab.db.models.detection import Detection


class DetectionReference(Base):
    __tablename__ = "detection_references"
    __table_args__ = (UniqueConstraint("detection_id", "url", name="uq_detection_reference_url"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    detection_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("detections.id"), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)

    detection: Mapped[Detection] = relationship(back_populates="references")
