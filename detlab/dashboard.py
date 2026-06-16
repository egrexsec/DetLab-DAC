from pathlib import Path
from string import Template

from detlab.analytics import ATTACK_TACTICS, generate_analytics
from detlab.models import Detection
from detlab.packs import list_pack_reports
from detlab.scoring import generate_score_report

HTML_TEMPLATE = Template("""
<!DOCTYPE html>
<html>
<head>
    <meta charset=\"utf-8\">
    <title>DetLab Detection Engineering Workbench</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 32px; }
        h1, h2, h3 { color: #f8fafc; }
        .eyebrow { color: #38bdf8; text-transform: uppercase; letter-spacing: 0.12em; font-size: 12px; font-weight: 700; }
        .section { margin-top: 32px; }
        .grid { display: grid; gap: 16px; }
        .cards { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        .card { background: #1e293b; border-radius: 16px; padding: 20px; box-shadow: 0 10px 20px rgba(15, 23, 42, 0.25); }
        .metric { font-size: 32px; font-weight: 700; margin-top: 8px; color: #f8fafc; }
        .heatmap { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
        .heat { border-radius: 12px; padding: 16px; min-height: 88px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid #334155; }
        th { color: #93c5fd; font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; }
        .pill { display: inline-block; border-radius: 999px; padding: 4px 10px; background: #0f172a; color: #cbd5e1; font-size: 12px; }
        ul { margin: 8px 0 0 18px; }
        .muted { color: #94a3b8; }
    </style>
</head>
<body>
    <div class=\"eyebrow\">Detection Engineering Workbench</div>
    <h1>DetLab Overview</h1>
    <p class=\"muted\">Build, validate, score, convert, test, and visualize detections from a single platform.</p>

    <section class=\"section\">
        <div class=\"grid cards\">
            <div class=\"card\"><h3>Total Detections</h3><div class=\"metric\">$total</div></div>
            <div class=\"card\"><h3>Coverage %</h3><div class=\"metric\">$coverage_percent%</div></div>
            <div class=\"card\"><h3>Average Detection Score</h3><div class=\"metric\">$average_score</div></div>
            <div class=\"card\"><h3>ATT&CK Techniques Covered</h3><div class=\"metric\">$techniques_covered</div></div>
            <div class=\"card\"><h3>Packs Installed</h3><div class=\"metric\">$packs_installed</div></div>
            <div class=\"card\"><h3>Validation Failures</h3><div class=\"metric\">$validation_failures</div></div>
        </div>
    </section>

    <section class=\"section\">
        <h2>ATT&CK Coverage Heatmap</h2>
        <div class=\"heatmap\">$heatmap</div>
        <div class=\"grid cards\" style=\"margin-top:16px\">
            <div class=\"card\"><h3>Coverage Gaps</h3>$coverage_gaps</div>
            <div class=\"card\"><h3>High-Risk Gaps</h3>$high_risk_gaps</div>
            <div class=\"card\"><h3>Weak Coverage</h3>$weak_coverage</div>
        </div>
    </section>

    <section class=\"section\">
        <h2>Detection Scoring</h2>
        <div class=\"card\">$score_table</div>
    </section>

    <section class=\"section\">
        <h2>Detection Packs</h2>
        <div class=\"grid cards\">$pack_cards</div>
    </section>
</body>
</html>
""")



def _heat_color(value: int) -> str:
    if value >= 3:
        return "#16a34a"
    if value >= 1:
        return "#f59e0b"
    return "#334155"



def _render_heatmap(tactics: dict[str, int]) -> str:
    items = []
    for tactic in ATTACK_TACTICS:
        value = tactics.get(tactic, 0)
        items.append(
            f'<div class="heat" style="background:{_heat_color(value)}"><strong>{tactic}</strong><div class="metric" style="font-size:26px">{value}</div></div>'
        )
    return "\n".join(items)



def _render_list(items: list[str]) -> str:
    if not items:
        return "<ul><li>None</li></ul>"
    return "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"



def _render_score_table(scores: list[dict]) -> str:
    rows = []
    for item in scores[:10]:
        rows.append(
            "<tr>"
            f"<td>{item['title']}</td>"
            f"<td>{item['coverage_score']}</td>"
            f"<td>{item['specificity_score']}</td>"
            f"<td>{item['metadata_score']}</td>"
            f"<td>{item['false_positive_risk_level']}</td>"
            f"<td>{item['overall_score']}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Detection</th><th>Coverage</th><th>Specificity</th><th>Documentation</th><th>False Positive Risk</th><th>Overall</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )



def _render_pack_cards(packs: list[dict]) -> str:
    if not packs:
        return '<div class="card"><p>No packs available.</p></div>'

    cards = []
    for pack in packs:
        cards.append(
            "<div class=\"card\">"
            f"<div class=\"pill\">{pack['pack_health']}</div>"
            f"<h3>{pack['title']}</h3>"
            f"<p class=\"muted\">{pack['description']}</p>"
            f"<p><strong>Detections:</strong> {pack['validation']['detection_count']}</p>"
            f"<p><strong>Average Score:</strong> {pack['average_score']}</p>"
            f"<p><strong>Platforms:</strong> {', '.join(pack['platforms']) if pack['platforms'] else 'None'}</p>"
            "</div>"
        )
    return "".join(cards)



def generate_dashboard(detections: list[Detection]) -> str:
    analytics = generate_analytics(detections)
    scores = generate_score_report(detections)
    packs = list_pack_reports(Path("examples/packs"))
    average_score = round(sum(item["overall_score"] for item in scores) / len(scores), 1) if scores else 0

    return HTML_TEMPLATE.substitute(
        total=analytics["total_detections"],
        coverage_percent=analytics["coverage_percent"],
        average_score=average_score,
        techniques_covered=len(analytics["techniques"]),
        packs_installed=len(packs),
        validation_failures=0,
        heatmap=_render_heatmap(analytics["tactics"]),
        coverage_gaps=_render_list(analytics["coverage_gaps"]),
        high_risk_gaps=_render_list(analytics["high_risk_gaps"]),
        weak_coverage=_render_list(analytics["weak_coverage"]),
        score_table=_render_score_table(scores),
        pack_cards=_render_pack_cards(packs),
    )
