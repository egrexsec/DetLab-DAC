from __future__ import annotations

from sqlalchemy import create_engine

from detlab.db.base import Base
from detlab.db.models import Detection, DetectionTag
from detlab.db.session import build_session_factory
from detlab.services.detection_service import DetectionService


def make_service() -> DetectionService:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = build_session_factory(engine)
    return DetectionService(session_factory)


def test_create_detection_persists_and_returns_detection():
    service = make_service()

    detection = service.create_detection(
        detection_id="DET-1000",
        slug="suspicious-logon",
        title="Suspicious Logon",
        description="Detect suspicious logon activity.",
        severity="high",
        status="production",
        author="DetLab",
        logsource_product="windows",
        logsource_service="security",
    )

    assert isinstance(detection, Detection)
    assert detection.id is not None
    assert detection.detection_id == "DET-1000"
    assert detection.slug == "suspicious-logon"
    assert detection.status == "production"


def test_list_published_detections_only_returns_published_records():
    service = make_service()

    service.create_detection(
        detection_id="DET-1001",
        slug="published-one",
        title="Published One",
        description="A published detection.",
        severity="medium",
        status="production",
        author="DetLab",
        logsource_product="windows",
        logsource_service="security",
    )
    service.create_detection(
        detection_id="DET-1002",
        slug="draft-one",
        title="Draft One",
        description="A draft detection.",
        severity="low",
        status="draft",
        author="DetLab",
        logsource_product="linux",
        logsource_service="auth",
    )
    service.create_detection(
        detection_id="DET-1003",
        slug="published-two",
        title="Published Two",
        description="Another published detection.",
        severity="high",
        status="production",
        author="DetLab",
        logsource_product="cloud",
        logsource_service=None,
    )

    detections = service.list_published_detections()

    assert [detection.slug for detection in detections] == ["published-one", "published-two"]
    assert {detection.status for detection in detections} == {"production"}


def test_get_published_detection_returns_loaded_relationships_after_session_close():
    service = make_service()

    service.create_detection(
        detection_id="DET-1004",
        slug="published-match",
        title="Published Match",
        description="Published detection.",
        severity="high",
        status="production",
        author="DetLab",
        logsource_product="windows",
        logsource_service="security",
        tags=[DetectionTag(tag="credential-access")],
    )
    service.create_detection(
        detection_id="DET-1005",
        slug="draft-match",
        title="Draft Match",
        description="Draft detection.",
        severity="medium",
        status="draft",
        author="DetLab",
        logsource_product="windows",
        logsource_service="sysmon",
    )

    published = service.get_published_detection("published-match")

    assert published is not None
    assert published.tags[0].tag == "credential-access"
    assert service.get_published_detection("draft-match") is None
    assert service.get_published_detection("missing") is None
