import json
from statistics import mean

from detlab.models import Detection

STATUS_SCORES = {
    "experimental": 45,
    "testing": 75,
    "stable": 90,
    "deprecated": 20,
}

SEVERITY_SCORES = {
    "low": 55,
    "medium": 70,
    "high": 82,
    "critical": 90,
}



def _selector_metrics(detection: Detection) -> tuple[int, int, bool]:
    selection = detection.detection.selection
    selector_count = len(selection)
    list_conditions = sum(1 for value in selection.values() if isinstance(value, list))
    has_event_guard = any(field.split("|")[0] in {"EventID", "EventCode"} for field in selection)
    return selector_count, list_conditions, has_event_guard



def _risk_level(value: int) -> str:
    if value >= 70:
        return "High"
    if value >= 40:
        return "Medium"
    return "Low"



def score_detection(detection: Detection) -> dict:
    selector_count, list_conditions, has_event_guard = _selector_metrics(detection)
    recommendations: list[str] = []

    coverage_score = 0
    if detection.attack.technique != "T0000":
        coverage_score += 45
    else:
        recommendations.append("Map the detection to a real ATT&CK technique")

    if detection.attack.tactic:
        coverage_score += 20
    else:
        recommendations.append("Add an ATT&CK tactic mapping")

    if detection.tests:
        coverage_score += 35
    else:
        recommendations.append("Add at least one validation or replay test")

    specificity_score = min(
        100,
        20 + (selector_count * 20) + (list_conditions * 10) + (20 if has_event_guard else 0),
    )
    if selector_count < 2:
        recommendations.append("Add additional selector fields to improve specificity")

    metadata_score = 0
    if detection.title:
        metadata_score += 20
    if detection.description:
        metadata_score += 20
    else:
        recommendations.append("Document what the detection is looking for")
    if detection.author:
        metadata_score += 15
    if detection.references:
        metadata_score += 20
    else:
        recommendations.append("Add reference material or ATT&CK source links")
    if detection.falsepositives:
        metadata_score += 15
    else:
        recommendations.append("Document expected false positives")
    metadata_score += 10 if detection.status in {"testing", "stable"} else 5

    maintainability_score = min(
        100,
        round(
            mean(
                [
                    STATUS_SCORES.get(detection.status, 30),
                    90 if detection.tests else 30,
                    85 if detection.references else 40,
                    80 if detection.falsepositives else 35,
                ]
            )
        ),
    )

    false_positive_risk = 75
    false_positive_risk -= min(selector_count * 12, 24)
    false_positive_risk -= min(list_conditions * 8, 16)
    false_positive_risk -= 12 if has_event_guard else 0
    false_positive_risk -= 12 if detection.falsepositives else 0
    false_positive_risk += 8 if detection.severity in {"critical", "high"} else 0
    false_positive_risk = max(10, min(95, false_positive_risk))

    overall_score = round(
        mean(
            [
                coverage_score,
                specificity_score,
                metadata_score,
                maintainability_score,
                100 - false_positive_risk,
            ]
        ),
        1,
    )

    if false_positive_risk >= 70:
        recommendations.append("Tighten broad matching logic to reduce false positive risk")

    return {
        "id": detection.id,
        "title": detection.title,
        "severity": detection.severity,
        "severity_score": SEVERITY_SCORES.get(detection.severity, 50),
        "status": detection.status,
        "coverage_score": coverage_score,
        "specificity_score": specificity_score,
        "metadata_score": metadata_score,
        "maintainability_score": maintainability_score,
        "false_positive_risk": false_positive_risk,
        "false_positive_risk_level": _risk_level(false_positive_risk),
        "overall_score": overall_score,
        "score": overall_score,
        "recommendations": recommendations,
    }



def generate_score_report(detections: list[Detection]) -> list[dict]:
    return sorted(
        [score_detection(detection) for detection in detections],
        key=lambda item: (-item["overall_score"], item["title"]),
    )



def generate_markdown_score_report(detections: list[Detection]) -> str:
    report = ["# Detection Score Report", ""]

    for result in generate_score_report(detections):
        report.extend(
            [
                f"## {result['title']}",
                f"- ID: {result['id']}",
                f"- Overall Score: {result['overall_score']}/100",
                f"- Coverage Score: {result['coverage_score']}/100",
                f"- Specificity Score: {result['specificity_score']}/100",
                f"- Metadata Score: {result['metadata_score']}/100",
                f"- Maintainability Score: {result['maintainability_score']}/100",
                f"- False Positive Risk: {result['false_positive_risk']}/100 ({result['false_positive_risk_level']})",
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
