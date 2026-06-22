import builtins
import importlib.util
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

from pytest import raises

from detlab.db.base import Base
from detlab.db.session import DatabaseConfig, build_engine, build_session_factory


ROOT = Path(__file__).resolve().parent.parent


def test_database_config_reads_env_and_builds_session_factory(monkeypatch):
    database_url = "postgresql+psycopg://detlab:secret@db.example:5432/detlab"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("SQLALCHEMY_ECHO", "true")

    config = DatabaseConfig.from_env()
    engine = build_engine(config)
    session_factory = build_session_factory(engine)

    assert config.database_url == database_url
    assert config.echo is True
    assert config.has_database is True
    assert engine.url.render_as_string(hide_password=False) == database_url
    assert engine.echo is True
    assert session_factory.kw["bind"] is engine


def test_database_config_is_opt_in_without_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)

    config = DatabaseConfig.from_env()

    assert config.database_url is None
    assert config.has_database is False
    assert Base.metadata is not None
    with raises(ValueError, match="DATABASE_URL is not configured"):
        build_engine(config)


def test_db_modules_fail_fast_when_sqlalchemy_is_unavailable(monkeypatch):
    original_import = builtins.__import__

    def raising_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith("sqlalchemy"):
            raise ModuleNotFoundError("No module named 'sqlalchemy'")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", raising_import)

    for module_name, module_path in {
        "detlab_db_base_missing_sqlalchemy": ROOT / "detlab" / "db" / "base.py",
        "detlab_db_session_missing_sqlalchemy": ROOT / "detlab" / "db" / "session.py",
    }.items():
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)

        with raises(ModuleNotFoundError, match="sqlalchemy"):
            spec.loader.exec_module(module)


def test_alembic_revision_smoke_test_succeeds_from_repo_assets(tmp_path):
    shutil.copy2(ROOT / "alembic.ini", tmp_path / "alembic.ini")
    shutil.copytree(ROOT / "alembic", tmp_path / "alembic")

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(tmp_path / "alembic.ini"), "revision", "-m", "smoke_test_db_foundation"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    revisions = sorted((tmp_path / "alembic" / "versions").glob("*.py"))
    assert revisions, "expected alembic revision file to be generated"
    assert all(path.name != ".gitkeep" for path in revisions)


def test_build_artifacts_include_alembic_assets(tmp_path):
    dist_dir = tmp_path / "dist"
    result = subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(dist_dir)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr

    sdist_path = next(dist_dir.glob("*.tar.gz"))
    with tarfile.open(sdist_path, "r:gz") as sdist:
        sdist_names = set(sdist.getnames())

    wheel_path = next(dist_dir.glob("*.whl"))
    with zipfile.ZipFile(wheel_path) as wheel:
        wheel_names = set(wheel.namelist())

    assert any(name.endswith("/alembic.ini") for name in sdist_names)
    assert any("/alembic/script.py.mako" in name for name in sdist_names)
    assert any("/alembic/env.py" in name for name in sdist_names)
    assert any(name.endswith("/alembic.ini") for name in wheel_names)
    assert any(name.endswith("/alembic/script.py.mako") for name in wheel_names)
    assert any(name.endswith("/alembic/env.py") for name in wheel_names)


def test_env_example_documents_sqlalchemy_echo():
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")

    assert "SQLALCHEMY_ECHO=" in env_example


def test_pyproject_declares_sqlalchemy_for_packaged_db_module():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '"SQLAlchemy>=2.0.0"' in pyproject.split("[project.optional-dependencies]", 1)[0]
