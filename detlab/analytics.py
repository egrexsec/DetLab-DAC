import json
from collections import Counter

from detlab.models import Detection
from detlab.scoring import score_detection



def generate_analytics(detections: list[Detection]) -> dict:
    tactic_counts = Counter()
    severity_counts = Counter()
    status_counts = Counter()
    score_ranges = {
        "90-100": 0,
        "70-89": 0,
        "50-69": 0,
        "0-49": 0,
    }

    weak_detections = []

    for detection in detections:
        tactic_counts[detection.attack.tactic] += 1
        severity_counts[detection.severity] += 1
        status_counts[detection.status] += 1

        score = score_detection(detection)["score"]

        if score >= 90:
            score_ranges["90-100"] += 1
        elif score >= 70:
            score_ranges["70-89"] += 1
        elif score >= 50:
            score_ranges["50-69"] += 1
        else:
            score_ranges["0-49"] += 1
            weak_detections.append(
                {
                    "id": detection.id,
                    "title": detection.title,
                    "score": score,
                }
            )

    return {
        "total_detections": len(detections),
        "tactics": dict(tactic_counts),
        "severity": dict(severity_counts),
        "status": dict(status_counts),
        "maturity_distribution": score_ranges,
        "weak_detections": weak_detections,
    }



def generate_markdown_analytics(detections: list[Detection]) -> str:
    analytics = generate_analytics(detections)

    report = [
        "# ATT&CK Coverage Analytics",
        "",
        f"Total Detections: {analytics['total_detections']}",
        "",
        "## Coverage by ATT&CK Tactic",
    ]

    for tactic, count in analytics["tactics"].items():
        report.append(f"- {tactic}: {count}")

    report.extend(["", "## Severity Distribution"])

    for severity, count in analytics["severity"].items():
        report.append(f"- {severity}: {count}")

    report.extend(["", "## Status Distribution"])

    for status, count in analytics["status"].items():
        report.append(f"- {status}: {count}")

    report.extend(["", "## Maturity Distribution"])

    for score_range, count in analytics["maturity_distribution"].items():
        report.append(f"- {score_range}: {count}")

    report.extend(["", "## Weak Detections"])

    if analytics["weak_detections"]:
        for weak in analytics["weak_detections"]:
            report.append(f"- {weak['title']} ({weak['score']}/100)")
    else:
        report.append("- None")

    return "\n".join(report)



def generate_json_analytics(detections: list[Detection]) -> str:
    return json.dumps(generate_analytics(detections), indent=2)
