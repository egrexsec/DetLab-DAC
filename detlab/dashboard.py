from detlab.analytics import generate_analytics
from detlab.models import Detection


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset=\"utf-8\">
    <title>DetLab Dashboard</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: #111827;
            color: #f3f4f6;
            margin: 40px;
        }}
        .card {{
            background: #1f2937;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
        }}
        h1, h2 {{
            color: #60a5fa;
        }}
        ul {{
            list-style-type: none;
            padding: 0;
        }}
        li {{
            margin-bottom: 8px;
        }}
    </style>
</head>
<body>
    <h1>DetLab Security Analytics Dashboard</h1>

    <div class=\"card\">
        <h2>Summary</h2>
        <p>Total Detections: {total}</p>
    </div>

    <div class=\"card\">
        <h2>ATT&CK Tactic Coverage</h2>
        <ul>
            {tactics}
        </ul>
    </div>

    <div class=\"card\">
        <h2>Severity Distribution</h2>
        <ul>
            {severity}
        </ul>
    </div>

    <div class=\"card\">
        <h2>Status Distribution</h2>
        <ul>
            {status}
        </ul>
    </div>

    <div class=\"card\">
        <h2>Maturity Distribution</h2>
        <ul>
            {maturity}
        </ul>
    </div>

    <div class=\"card\">
        <h2>Weak Detections</h2>
        <ul>
            {weak}
        </ul>
    </div>
</body>
</html>
"""



def _render_list(items: dict) -> str:
    return "\n".join([f"<li>{k}: {v}</li>" for k, v in items.items()])



def generate_dashboard(detections: list[Detection]) -> str:
    analytics = generate_analytics(detections)

    weak = analytics["weak_detections"]

    weak_html = (
        "\n".join(
            [f"<li>{item['title']} ({item['score']}/100)</li>" for item in weak]
        )
        if weak
        else "<li>None</li>"
    )

    return HTML_TEMPLATE.format(
        total=analytics["total_detections"],
        tactics=_render_list(analytics["tactics"]),
        severity=_render_list(analytics["severity"]),
        status=_render_list(analytics["status"]),
        maturity=_render_list(analytics["maturity_distribution"]),
        weak=weak_html,
    )
