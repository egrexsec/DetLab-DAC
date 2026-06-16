from pathlib import Path
import json

import yaml

from detlab.analytics import generate_analytics
from detlab.scoring import generate_score_report
from detlab.validators import load_detection_dir, load_detection_file

REQUIRED_PACK_FIELDS = [
    "name",
    "version",
    "maintainer",
    "description",
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
    validation = validate_pack(pack_dir)
    detection_dir = pack_dir / "detections"

    detections = [load_detection_file(path) for path in detection_dir.rglob("*.y*ml")]
    analytics = generate_analytics(detections)
    scores = generate_score_report(detections)

    average_score = round(
        sum(item["overall_score"] for item in scores) / len(scores),
        1,
    ) if scores else 0

    return {
        "name": manifest.get("name"),
        "title": manifest.get("title", manifest.get("name")),
        "version": manifest.get("version"),
        "maintainer": manifest.get("maintainer"),
        "description": manifest.get("description", ""),
        "platforms": manifest.get("platforms", []),
        "focus_areas": manifest.get("focus_areas", []),
        "dependencies": manifest.get("dependencies", []),
        "validation": validation,
        "analytics": analytics,
        "average_score": average_score,
        "pack_health": "healthy" if validation["manifest_valid"] and validation["detections_valid"] else "needs-attention",
    }



def list_pack_reports(root: Path = Path("examples/packs")) -> list[dict]:
    if not root.exists():
        return []

    reports = [generate_pack_report(pack_dir) for pack_dir in sorted(root.iterdir()) if pack_dir.is_dir()]
    return sorted(reports, key=lambda item: item["name"])



def render_pack_report_markdown(report: dict) -> str:
    lines = [
        f"# Detection Pack: {report['title']}",
        "",
        f"Version: {report['version']}",
        f"Maintainer: {report['maintainer']}",
        f"Average Score: {report['average_score']}",
        f"Pack Health: {report['pack_health']}",
        "",
        report["description"],
        "",
        "## Supported Platforms",
    ]

    for platform in report["platforms"]:
        lines.append(f"- {platform}")

    lines.extend(["", "## Focus Areas"])
    for focus_area in report["focus_areas"]:
        lines.append(f"- {focus_area}")

    lines.extend(["", "## ATT&CK Tactics"])
    for tactic, count in report["analytics"]["tactics"].items():
        if count:
            lines.append(f"- {tactic}: {count}")

    lines.extend(["", "## Severity Distribution"])
    for severity, count in report["analytics"]["severity"].items():
        lines.append(f"- {severity}: {count}")

    return "\n".join(lines)



def render_pack_report_json(report: dict) -> str:
    return json.dumps(report, indent=2)
