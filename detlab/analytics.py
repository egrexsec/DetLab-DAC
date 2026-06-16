import json
from collections import Counter

from detlab.models import Detection
from detlab.scoring import generate_score_report

ATTACK_TACTICS = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

HIGH_RISK_TACTIC_GAPS = [
    "credential-access",
    "privilege-escalation",
    "lateral-movement",
    "command-and-control",
    "exfiltration",
]



def generate_analytics(detections: list[Detection]) -> dict:
    tactic_counts = Counter({tactic: 0 for tactic in ATTACK_TACTICS})
    technique_counts = Counter()
    platform_counts = Counter()
    severity_counts = Counter()
    status_counts = Counter()
    score_ranges = {
        "90-100": 0,
        "70-89": 0,
        "50-69": 0,
        "0-49": 0,
    }

    score_report = generate_score_report(detections)
    weak_detections = []

    for detection, score in zip(detections, score_report):
        tactic_counts[detection.attack.tactic] += 1
        technique_counts[detection.attack.technique] += 1
        platform_counts[detection.logsource.product] += 1
        severity_counts[detection.severity] += 1
        status_counts[detection.status] += 1

        overall = score["overall_score"]
        if overall >= 90:
            score_ranges["90-100"] += 1
        elif overall >= 70:
            score_ranges["70-89"] += 1
        elif overall >= 50:
            score_ranges["50-69"] += 1
        else:
            score_ranges["0-49"] += 1

        if overall < 70:
            weak_detections.append(
                {
                    "id": detection.id,
                    "title": detection.title,
                    "score": overall,
                }
            )

    covered_tactics = {tactic for tactic, count in tactic_counts.items() if count > 0}
    coverage_percent = round((len(covered_tactics) / len(ATTACK_TACTICS)) * 100, 1) if ATTACK_TACTICS else 0
    coverage_gaps = [tactic for tactic in ATTACK_TACTICS if tactic_counts[tactic] == 0]
    weak_coverage = [tactic for tactic in ATTACK_TACTICS if tactic_counts[tactic] == 1]
    high_risk_gaps = [tactic for tactic in HIGH_RISK_TACTIC_GAPS if tactic in coverage_gaps]

    return {
        "total_detections": len(detections),
        "tactics": dict(tactic_counts),
        "techniques": dict(technique_counts),
        "platforms": dict(platform_counts),
        "severity": dict(severity_counts),
        "status": dict(status_counts),
        "maturity_distribution": score_ranges,
        "coverage_percent": coverage_percent,
        "coverage_gaps": coverage_gaps,
        "weak_coverage": weak_coverage,
        "high_risk_gaps": high_risk_gaps,
        "weak_detections": weak_detections,
    }



def generate_markdown_analytics(detections: list[Detection]) -> str:
    analytics = generate_analytics(detections)

    report = [
        "# ATT&CK Coverage Report",
        "",
        f"Total Detections: {analytics['total_detections']}",
        f"Coverage Percent: {analytics['coverage_percent']}%",
        f"ATT&CK Techniques Covered: {len(analytics['techniques'])}",
        "",
        "## Coverage by ATT&CK Tactic",
    ]

    for tactic, count in analytics["tactics"].items():
        report.append(f"- {tactic}: {count}")

    report.extend(["", "## Coverage by Technique"])
    for technique, count in analytics["techniques"].items():
        report.append(f"- {technique}: {count}")

    report.extend(["", "## Coverage by Platform"])
    for platform, count in analytics["platforms"].items():
        report.append(f"- {platform}: {count}")

    report.extend(["", "## Coverage Gaps"])
    if analytics["coverage_gaps"]:
        for tactic in analytics["coverage_gaps"]:
            report.append(f"- {tactic}")
    else:
        report.append("- None")

    report.extend(["", "## High-Risk Gaps"])
    if analytics["high_risk_gaps"]:
        for tactic in analytics["high_risk_gaps"]:
            report.append(f"- {tactic}")
    else:
        report.append("- None")

    report.extend(["", "## Weak Detections"])
    if analytics["weak_detections"]:
        for weak in analytics["weak_detections"]:
            report.append(f"- {weak['title']} ({weak['score']}/100)")
    else:
        report.append("- None")

    return "\n".join(report)



def generate_json_analytics(detections: list[Detection]) -> str:
    return json.dumps(generate_analytics(detections), indent=2)
