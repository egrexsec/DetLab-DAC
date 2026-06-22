from __future__ import annotations

from sqlalchemy.orm import sessionmaker

from detlab.db.models import Detection
from detlab.db.repositories.detection_repository import DetectionRepository


class DetectionService:
    def __init__(self, session_factory: sessionmaker, published_status: str = "production"):
        self.session_factory = session_factory
        self.published_status = published_status

    def create_detection(self, **detection_fields: object) -> Detection:
        with self.session_factory() as session:
            repository = DetectionRepository(session)
            return repository.create_detection(**detection_fields)

    def list_published_detections(self) -> list[Detection]:
        with self.session_factory() as session:
            repository = DetectionRepository(session)
            return list(repository.list_by_status(self.published_status))

    def get_published_detection(self, slug: str) -> Detection | None:
        with self.session_factory() as session:
            repository = DetectionRepository(session)
            return repository.get_by_slug_and_status(slug, self.published_status)
