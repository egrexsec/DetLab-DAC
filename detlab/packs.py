from pathlib import Path
import json

import yaml

from detlab.analytics import generate_analytics
from detlab.scoring import generate_score_report
from detlab.validators import load_detection_dir

REQUIRED_PACK_FIELDS = [
    "name",
    "version",
    "maintainer",
    "platforms",
]



def load_pack_manifest(pack_dir: Path) -> dict:
    manifest_path = pack_dir / "pack.yml"

    if not manifest_path.exists():
        raise FileNotFoundError("pack.yml not found")

    return yaml.safe_load(manifest_path.read_text(encoding="utf-8"))



def validate_pack_manifest(manifest: dict) -> list[str]:
    errors = []

    for field in REQUIRED_PACK_FIELDS:
        if field not in manifest:
            errors.append(f"Missing required field: {field}")

    return errors



def validate_pack(pack_dir: Path) -> dict:
    manifest = load_pack_manifest(pack_dir)
    manifest_errors = validate_pack_manifest(manifest)

    detection_dir = pack_dir / "detections"

    files, valid, detection_errors = load_detection_dir(detection_dir)

    return {
        "manifest_valid": len(manifest_errors) == 0,
        "manifest_errors": manifest_errors,
        "detections_valid": valid,
        "detection_count": len(files),
        "detection_errors": detection_errors,
    }



def generate_pack_report(pack_dir: Path) -> dict:
    manifest = load_pack_manifest(pack_dir)

    detection_dir = pack_dir / "detections"

    detections = []

    for path in detection_dir.rglob("*.y*ml"):
        from detlab.validators import load_detection_file

        detections.append(load_detection_file(path))

    analytics = generate_analytics(detections)
    scores = generate_score_report(detections)

    average_score = (
        sum([item["score"] for item in scores]) / len(scores)
        if scores
        else 0
    )

    return {
        "name": manifest.get("name"),
        "version": manifest.get("version"),
        "maintainer": manifest.get("maintainer"),
        "platforms": manifest.get("platforms", []),
        "dependencies": manifest.get("dependencies", []),
        "analytics": analytics,
        "average_score": round(average_score, 2),
    }



def render_pack_report_markdown(report: dict) -> str:
    lines = [
        f"# Detection Pack: {report['name']}",
        "",
        f"Version: {report['version']}",
        f"Maintainer: {report['maintainer']}",
        f"Average Score: {report['average_score']}",
        "",
        "## Supported Platforms",
    ]

    for platform in report["platforms"]:
        lines.append(f"- {platform}")

    lines.extend(["", "## ATT&CK Tactics"])

    for tactic, count in report["analytics"]["tactics"].items():
        lines.append(f"- {tactic}: {count}")

    lines.extend(["", "## Severity Distribution"])

    for severity, count in report["analytics"]["severity"].items():
        lines.append(f"- {severity}: {count}")

    return "\n".join(lines)



def render_pack_report_json(report: dict) -> str:
    return json.dumps(report, indent=2)
