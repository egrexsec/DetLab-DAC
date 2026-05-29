import json
from pathlib import Path

from detlab.trust import generate_trust_metadata, verify_checksum, verify_pack
from detlab.registry import calculate_checksum


def test_verify_checksum(tmp_path: Path):
    archive = tmp_path / "pack.tar.gz"
    archive.write_text("detlab-pack", encoding="utf-8")

    checksum = calculate_checksum(archive)

    assert verify_checksum(archive, checksum) is True


def test_verify_pack(tmp_path: Path):
    archive = tmp_path / "windows-core-1.0.0.tar.gz"
    archive.write_text("detlab-pack", encoding="utf-8")

    checksum = calculate_checksum(archive)

    metadata = {
        "name": "windows-core",
        "version": "1.0.0",
        "checksum": checksum,
        "archive": archive.name,
    }

    metadata_path = tmp_path / "windows-core.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    result = verify_pack(archive, metadata_path)

    assert result["verified"] is True
    assert result["name"] == "windows-core"


def test_generate_trust_metadata():
    metadata = generate_trust_metadata("windows-core", "1.0.0", "abc123")

    assert metadata["name"] == "windows-core"
    assert metadata["trust"]["algorithm"] == "sha256"
    assert metadata["trust"]["verified"] is True
