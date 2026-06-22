from __future__ import annotations

import importlib.util
from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
from sqlalchemy.schema import MetaData

from detlab.db.base import Base


ROOT = Path(__file__).resolve().parent.parent


def test_detection_models_register_expected_tables_and_relationships():
    from detlab.db.models import (
        AttackTechnique,
        Detection,
        DetectionAttackMapping,
        DetectionLogicVariant,
        DetectionReference,
        DetectionTag,
    )

    expected_tables = {
        "attack_tactics",
        "attack_techniques",
        "detections",
        "detection_attack_mappings",
        "detection_logic_variants",
        "detection_references",
        "detection_tags",
    }

    assert expected_tables.issubset(Base.metadata.tables)
    assert AttackTechnique.__table__.c.tactic_id.foreign_keys
    assert DetectionAttackMapping.__table__.c.detection_id.foreign_keys
    assert DetectionAttackMapping.__table__.c.technique_id.foreign_keys
    assert DetectionLogicVariant.__table__.c.detection_id.foreign_keys
    assert DetectionReference.__table__.c.detection_id.foreign_keys
    assert DetectionTag.__table__.c.detection_id.foreign_keys
    assert Detection.slug.property.columns[0].unique is True
    assert Detection.detection_id.property.columns[0].unique is True



def test_detection_models_create_sqlite_schema_and_persist_mappings():
    from detlab.db.models import AttackTactic, AttackTechnique, Detection, DetectionAttackMapping

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    inspector = inspect(engine)
    assert set(inspector.get_table_names()) >= {
        "attack_tactics",
        "attack_techniques",
        "detections",
        "detection_attack_mappings",
        "detection_logic_variants",
        "detection_references",
        "detection_tags",
    }

    with Session(engine) as session:
        tactic = AttackTactic(attack_id="TA0001", name="Initial Access", short_name="initial-access")
        technique = AttackTechnique(
            attack_id="T1078",
            name="Valid Accounts",
            tactic=tactic,
            detection_mappings=[DetectionAttackMapping(role="primary")],
        )
        detection = Detection(
            detection_id="DET-0001",
            slug="valid-accounts-detection",
            title="Valid Accounts Detection",
            description="Detects suspicious valid account use.",
            severity="high",
            status="production",
            author="DetLab",
            logsource_product="windows",
            logsource_service="security",
            attack_mappings=technique.detection_mappings,
        )

        session.add(detection)
        session.commit()
        session.refresh(detection)

        assert detection.id is not None
        assert detection.created_at is not None
        assert detection.updated_at is not None
        assert detection.attack_mappings[0].technique.attack_id == "T1078"
        assert detection.attack_mappings[0].role == "primary"
        assert technique.tactic.attack_id == "TA0001"



def test_initial_detection_schema_migration_defines_expected_revision_metadata():
    migration_path = ROOT / "alembic" / "versions" / "0001_initial_detection_schema.py"
    spec = importlib.util.spec_from_file_location("initial_detection_schema", migration_path)

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.revision == "0001_initial_detection_schema"
    assert module.down_revision is None
    assert callable(module.upgrade)
    assert callable(module.downgrade)


def test_detection_logic_variants_migration_defines_expected_revision_metadata():
    migration_path = ROOT / "alembic" / "versions" / "0002_add_detection_logic_variants.py"
    spec = importlib.util.spec_from_file_location("add_detection_logic_variants", migration_path)

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.revision == "0002_add_detection_logic_variants"
    assert module.down_revision == "0001_initial_detection_schema"
    assert callable(module.upgrade)
    assert callable(module.downgrade)



def test_initial_detection_schema_migration_matches_model_metadata(tmp_path):
    import detlab.db.models  # noqa: F401

    migration_paths = [
        ROOT / "alembic" / "versions" / "0001_initial_detection_schema.py",
        ROOT / "alembic" / "versions" / "0002_add_detection_logic_variants.py",
    ]
    modules = []
    for index, migration_path in enumerate(migration_paths, start=1):
        spec = importlib.util.spec_from_file_location(f"migration_runtime_{index}", migration_path)

        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)

    sqlite_path = tmp_path / "detlab.db"
    engine = create_engine(f"sqlite+pysqlite:///{sqlite_path}")

    with engine.begin() as connection:
        migration_context = MigrationContext.configure(connection)
        for module in modules:
            with module.op.Operations.context(migration_context):
                module.upgrade()

    reflected_metadata = MetaData()
    reflected_metadata.reflect(bind=engine)

    with engine.connect() as connection:
        migration_context = MigrationContext.configure(connection)
        diffs = compare_metadata(migration_context, Base.metadata)

    assert set(reflected_metadata.tables) >= {
        "attack_tactics",
        "attack_techniques",
        "detections",
        "detection_attack_mappings",
        "detection_logic_variants",
        "detection_references",
        "detection_tags",
    }
    assert diffs == []
