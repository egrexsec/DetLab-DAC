import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from detlab.analytics import generate_analytics
from detlab.domain import (
    build_detection_catalog,
    build_detection_workspace,
    export_domain_schema,
    load_detections,
)
from detlab.markdown_ingest import markdown_source_files
from detlab.processing import (
    UnsupportedConversionTargetError,
    convert_detection_content,
    inspect_detection_content,
)
from detlab.scoring import generate_score_report
from detlab.sources import describe_detection_source, resolve_detection_dir
from detlab.validators import load_detection_dir

ROOT_PATH = os.getenv("DETLAB_ROOT_PATH", "")
MAX_DETECTION_REQUEST_BYTES = 25_000

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
    return load_detections(str(resolve_detection_dir(path)))



def _build_review_queue(analytics_data: dict, score_data: list[dict]) -> dict:
    high_risk_gaps = [
        {
            "tactic": tactic,
            "priority": "high",
            "recommended_source_path": f"detections/{tactic}",
            "recommended_action": f"Add or expand detections covering the {tactic} ATT&CK tactic in the GitHub-backed detection directory.",
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
    resolved_path = resolve_detection_dir(path)
    yaml_files = list(Path(resolved_path).rglob("*.y*ml"))
    if yaml_files:
        files, valid, errors = load_detection_dir(Path(resolved_path))
    else:
        files = markdown_source_files(resolved_path)
        valid = bool(files)
        errors = {}
    detections = _load_detections(str(resolved_path))
    analytics_data = generate_analytics(detections)
    score_data = generate_score_report(detections)
    source_status = describe_detection_source(path)

    return {
        "summary": {
            "total_detections": analytics_data.get("total_detections", 0),
            "coverage_percent": analytics_data.get("coverage_percent", 0),
            "average_detection_score": round(
                sum(item["overall_score"] for item in score_data) / len(score_data),
                1,
            ) if score_data else 0,
            "attack_techniques_covered": len(analytics_data.get("techniques", {})),
            "source_mode": source_status["mode"],
            "validation_failures": len(errors),
        },
        "source": source_status,
        "coverage": {
            "by_tactic": analytics_data.get("tactics", {}),
            "by_technique": analytics_data.get("techniques", {}),
            "by_platform": analytics_data.get("platforms", {}),
            "coverage_gaps": analytics_data.get("coverage_gaps", []),
            "weak_coverage": analytics_data.get("weak_coverage", []),
            "high_risk_gaps": analytics_data.get("high_risk_gaps", []),
        },
        "scoring": score_data,
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


@app.get("/source")
def source(path: str = "detections"):
    return describe_detection_source(path)


@app.get("/dashboard")
def dashboard(path: str = "detections"):
    return _build_dashboard_payload(path)


@app.get("/schema/domain")
def domain_schema():
    return export_domain_schema()


@app.get("/detections/catalog")
def detection_catalog(path: str = "detections"):
    return build_detection_catalog(path)


@app.get("/detections/{detection_id}/workspace")
def detection_workspace(detection_id: str, path: str = "detections"):
    workspace = build_detection_workspace(detection_id, path)
    if workspace is None:
        raise HTTPException(status_code=404, detail=f"Detection not found: {detection_id}")
    return workspace


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
