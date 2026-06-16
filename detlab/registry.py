import hashlib
import json
import tarfile
from pathlib import Path

from detlab.packs import load_pack_manifest

LOCAL_REGISTRY = Path(".detlab/registry")



def calculate_checksum(path: Path) -> str:
    sha256 = hashlib.sha256()

    with path.open("rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)

    return sha256.hexdigest()



def build_pack(pack_dir: Path, output_dir: Path = Path("dist")) -> Path:
    manifest = load_pack_manifest(pack_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    archive_name = f"{manifest['name']}-{manifest['version']}.tar.gz"
    archive_path = output_dir / archive_name

    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(pack_dir, arcname=pack_dir.name)

    checksum = calculate_checksum(archive_path)

    metadata = {
        "name": manifest["name"],
        "version": manifest["version"],
        "checksum": checksum,
        "platforms": manifest.get("platforms", []),
    }

    metadata_path = output_dir / f"{manifest['name']}-{manifest['version']}.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return archive_path



def install_pack(archive_path: Path, install_dir: Path = LOCAL_REGISTRY) -> Path:
    install_dir.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(path=install_dir)

    return install_dir



def publish_pack(pack_dir: Path, registry_dir: Path = Path("registry")) -> dict:
    registry_dir.mkdir(parents=True, exist_ok=True)

    archive = build_pack(pack_dir, registry_dir)

    checksum = calculate_checksum(archive)

    manifest = load_pack_manifest(pack_dir)

    published_metadata = {
        "name": manifest["name"],
        "version": manifest["version"],
        "checksum": checksum,
        "archive": archive.name,
    }

    metadata_file = registry_dir / f"{manifest['name']}.json"
    metadata_file.write_text(
        json.dumps(published_metadata, indent=2),
        encoding="utf-8",
    )

    return published_metadata
