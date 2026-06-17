import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from detlab.analytics import generate_analytics
from detlab.packs import list_pack_reports
from detlab.processing import (
    UnsupportedConversionTargetError,
    convert_detection_content,
    inspect_detection_content,
)
from detlab.scoring import generate_score_report
from detlab.validators import load_detection_dir, load_detection_file

ROOT_PATH = os.getenv("DETLAB_ROOT_PATH", "")
PACK_ROOT = Path(os.getenv("DETLAB_PACK_ROOT", "examples/packs"))
MAX_DETECTION_REQUEST_BYTES = 25_000

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


@app.middleware("http")
async def reject_oversized_detection_requests(request: Request, call_next):
    if request.url.path.endswith("/detections/inspect") or request.url.path.endswith("/detections/convert"):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})
            if declared_length > MAX_DETECTION_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Detection request body exceeds {MAX_DETECTION_REQUEST_BYTES} bytes"},
                )
    return await call_next(request)


class DetectionInspectRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=20000)


class DetectionConvertRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=20000)
    target: str = Field(..., min_length=1, max_length=32)



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


@app.post("/detections/inspect")
def inspect_detection(request: DetectionInspectRequest):
    result = inspect_detection_content(request.content)
    if result["valid"]:
        return result
    return JSONResponse(status_code=422, content=result)


@app.post("/detections/convert")
def convert_detection(request: DetectionConvertRequest):
    try:
        result = convert_detection_content(request.content, request.target)
    except UnsupportedConversionTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if result["valid"]:
        return result
    return JSONResponse(status_code=422, content=result)
