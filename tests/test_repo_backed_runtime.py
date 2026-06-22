from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_env_example_only_documents_repo_backed_runtime_settings():
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")

    assert "DATABASE_URL=" not in env_example
    assert "SQLALCHEMY_ECHO=" not in env_example
    assert "DETLAB_ROOT_PATH=" in env_example
    assert "NEXT_PUBLIC_API_BASE_URL=" in env_example


def test_pyproject_does_not_package_database_stack_dependencies_or_assets():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    forbidden_fragments = [
        '"SQLAlchemy>=2.0.0"',
        '"alembic>=1.13.0"',
        '"psycopg[binary]>=3.1.0"',
        '"" = ["alembic.ini"]',
        '"alembic" = ["alembic/env.py", "alembic/script.py.mako"]',
    ]

    for fragment in forbidden_fragments:
        assert fragment not in pyproject


def test_repo_no_longer_tracks_database_runtime_modules_or_migrations():
    assert not (ROOT / "detlab" / "db").exists()
    assert not (ROOT / "detlab" / "services" / "detection_service.py").exists()
    assert not (ROOT / "detlab" / "services" / "detection_ingest_service.py").exists()
    assert not (ROOT / "alembic").exists()
    assert not (ROOT / "alembic.ini").exists()
