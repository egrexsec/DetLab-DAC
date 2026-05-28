from pathlib import Path

import tomllib


ROOT = Path(__file__).resolve().parent.parent


def test_project_metadata_exists():
    pyproject = ROOT / "pyproject.toml"

    assert pyproject.exists()

    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)

    project = data["project"]

    assert project["name"] == "detlab"
    assert project["version"]
    assert project["requires-python"] == ">=3.11"


def test_project_urls_exist():
    pyproject = ROOT / "pyproject.toml"

    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)

    urls = data["project"]["urls"]

    assert "Homepage" in urls
    assert "Repository" in urls
    assert "Issues" in urls


def test_console_script_exists():
    pyproject = ROOT / "pyproject.toml"

    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)

    scripts = data["project"]["scripts"]

    assert scripts["detlab"] == "detlab.main:app"
