import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from detlab.analytics import generate_analytics
from detlab.packs import list_pack_reports
from detlab.scoring import generate_score_report
from detlab.validators import load_detection_dir, load_detection_file

ROOT_PATH = os.getenv("DETLAB_ROOT_PATH", "")
PACK_ROOT = Path(os.getenv("DETLAB_PACK_ROOT", "examples/packs"))

TACTIC_PACK_MAP = {
    "credential-access": "credential-access",
    "privilege-escalation": "windows-core",
    "lateral-movement": "windows-core",
    "command-and-control": "powershell",
    "exfiltration": "cloudtrail",
    "initial-access": "windows-core",
    "persistence": "persistence",
}

app = FastAPI(title="DetLab API", version="0.1.0", root_path=ROOT_PATH)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



def _load_detections(path: str):
    return [load_detection_file(file_path) for file_path in Path(path).rglob("*.y*ml")]



def _build_review_queue(analytics_data: dict, score_data: list[dict]) -> dict:
    high_risk_gaps = [
        {
            "tactic": tactic,
            "priority": "high",
            "recommended_pack": TACTIC_PACK_MAP.get(tactic, "windows-core"),
            "recommended_action": f"Add or expand detections covering the {tactic} ATT&CK tactic.",
        }
        for tactic in analytics_data.get("high_risk_gaps", [])
    ]
    weak_detections = [
        {
            "id": item["id"],
            "title": item["title"],
            "overall_score": item["overall_score"],
            "severity": item["severity"],
            "status": item["status"],
            "recommendations": item["recommendations"],
        }
        for item in score_data
        if item["overall_score"] < 70
    ]
    return {
        "high_risk_gaps": high_risk_gaps,
        "weak_detections": weak_detections,
    }



def _build_dashboard_payload(path: str = "detections") -> dict:
    files, valid, errors = load_detection_dir(Path(path))
    detections = _load_detections(path)
    analytics_data = generate_analytics(detections)
    score_data = generate_score_report(detections)
    pack_reports = list_pack_reports(PACK_ROOT)

    return {
        "summary": {
            "total_detections": analytics_data.get("total_detections", 0),
            "coverage_percent": analytics_data.get("coverage_percent", 0),
            "average_detection_score": round(
                sum(item["overall_score"] for item in score_data) / len(score_data),
                1,
            ) if score_data else 0,
            "attack_techniques_covered": len(analytics_data.get("techniques", {})),
            "packs_installed": len(pack_reports),
            "validation_failures": len(errors),
        },
        "coverage": {
            "by_tactic": analytics_data.get("tactics", {}),
            "by_technique": analytics_data.get("techniques", {}),
            "by_platform": analytics_data.get("platforms", {}),
            "coverage_gaps": analytics_data.get("coverage_gaps", []),
            "weak_coverage": analytics_data.get("weak_coverage", []),
            "high_risk_gaps": analytics_data.get("high_risk_gaps", []),
        },
        "scoring": score_data,
        "packs": pack_reports,
        "review_queue": _build_review_queue(analytics_data, score_data),
        "reports": {
            "valid": valid,
            "files": [str(file) for file in files],
            "errors": {str(k): v for k, v in errors.items()},
            "severity": analytics_data.get("severity", {}),
            "status": analytics_data.get("status", {}),
            "score_distribution": analytics_data.get("maturity_distribution", {}),
            "weak_detections": analytics_data.get("weak_detections", []),
        },
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/validate")
def validate(path: str = "detections"):
    files, valid, errors = load_detection_dir(Path(path))

    return {
        "valid": valid,
        "files": [str(file) for file in files],
        "errors": {str(k): v for k, v in errors.items()},
    }


@app.get("/analytics")
def analytics(path: str = "detections"):
    return generate_analytics(_load_detections(path))


@app.get("/score")
def score(path: str = "detections"):
    return generate_score_report(_load_detections(path))


@app.get("/packs")
def packs():
    return list_pack_reports(PACK_ROOT)


@app.get("/dashboard")
def dashboard(path: str = "detections"):
    return _build_dashboard_payload(path)
