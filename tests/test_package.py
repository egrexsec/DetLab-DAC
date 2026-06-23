from pathlib import Path

import tomllib


ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_is_repo_runtime_metadata_not_packaging_metadata():
    pyproject = ROOT / "pyproject.toml"

    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)

    assert "build-system" not in data
    assert data["tool"]["uv"]["package"] is False
    assert "scripts" not in data["project"]

    dev_deps = data["project"]["optional-dependencies"]["dev"]
    assert "build>=1.2.0" not in dev_deps
    assert "twine>=5.0.0" not in dev_deps


def test_release_workflow_is_removed_for_website_first_repo():
    assert not (ROOT / ".github" / "workflows" / "release.yml").exists()


def test_ci_installs_repo_dependencies_without_editable_package_install():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "astral-sh/setup-uv" in workflow
    assert "uv sync --all-extras" in workflow
    assert "pip install -e .[dev]" not in workflow
    assert "python -m build" not in workflow
