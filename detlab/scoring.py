import json

from detlab.models import Detection

STATUS_SCORES = {
    "experimental": 5,
    "testing": 10,
    "stable": 15,
    "deprecated": 0,
}

SEVERITY_SCORES = {
    "low": 5,
    "medium": 8,
    "high": 10,
    "critical": 10,
}



def score_detection(detection: Detection) -> dict:
    score = 0
    recommendations = []

    if detection.title and detection.description:
        score += 15
    else:
        recommendations.append("Add title and description metadata")

    if detection.attack.technique != "T0000":
        score += 20
    else:
        recommendations.append("Map detection to ATT&CK technique")

    if detection.tests:
        score += 20
    else:
        recommendations.append("Add validation tests")

    if detection.references:
        score += 10
    else:
        recommendations.append("Add external references")

    if detection.falsepositives:
        score += 10
    else:
        recommendations.append("Document false positives")

    score += STATUS_SCORES.get(detection.status, 0)
    score += SEVERITY_SCORES.get(detection.severity, 0)

    if detection.detection:
        score += 15
    else:
        recommendations.append("Add detection logic")

    score = min(score, 100)

    return {
        "id": detection.id,
        "title": detection.title,
        "score": score,
        "severity": detection.severity,
        "status": detection.status,
        "recommendations": recommendations,
    }



def generate_score_report(detections: list[Detection]) -> list[dict]:
    return [score_detection(detection) for detection in detections]



def generate_markdown_score_report(detections: list[Detection]) -> str:
    report = ["# Detection Maturity Report", ""]

    for result in generate_score_report(detections):
        report.extend(
            [
                f"## {result['title']}",
                f"- ID: {result['id']}",
                f"- Score: {result['score']}/100",
                f"- Severity: {result['severity']}",
                f"- Status: {result['status']}",
                "- Recommendations:",
            ]
        )

        if result["recommendations"]:
            for recommendation in result["recommendations"]:
                report.append(f"  - {recommendation}")
        else:
            report.append("  - None")

        report.append("")

    return "\n".join(report)



def generate_json_score_report(detections: list[Detection]) -> str:
    return json.dumps(generate_score_report(detections), indent=2)
