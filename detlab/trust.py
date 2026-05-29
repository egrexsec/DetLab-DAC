from pathlib import Path
import json

from detlab.registry import calculate_checksum



def load_metadata(metadata_path: Path) -> dict:
    return json.loads(metadata_path.read_text(encoding="utf-8"))



def verify_checksum(archive_path: Path, expected_checksum: str) -> bool:
    calculated = calculate_checksum(archive_path)
    return calculated == expected_checksum



def verify_pack(archive_path: Path, metadata_path: Path) -> dict:
    metadata = load_metadata(metadata_path)

    expected_checksum = metadata.get("checksum")
    verified = verify_checksum(archive_path, expected_checksum)

    return {
        "name": metadata.get("name"),
        "version": metadata.get("version"),
        "verified": verified,
        "checksum": expected_checksum,
        "archive": archive_path.name,
    }



def generate_trust_metadata(name: str, version: str, checksum: str) -> dict:
    return {
        "name": name,
        "version": version,
        "checksum": checksum,
        "trust": {
            "verified": True,
            "algorithm": "sha256",
        },
    }
