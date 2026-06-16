from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from detlab.analytics import generate_analytics
from detlab.scoring import generate_score_report
from detlab.validators import load_detection_dir, load_detection_file

app = FastAPI(title="DetLab API", version="0.1.0")

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
    detections = [
        load_detection_file(p)
        for p in Path(path).rglob("*.y*ml")
    ]

    return generate_analytics(detections)


@app.get("/score")
def score(path: str = "detections"):
    detections = [
        load_detection_file(p)
        for p in Path(path).rglob("*.y*ml")
    ]

    return generate_score_report(detections)


@app.get("/dashboard")
def dashboard(path: str = "detections"):
    detections = [
        load_detection_file(p)
        for p in Path(path).rglob("*.y*ml")
    ]

    analytics_data = generate_analytics(detections)
    score_data = generate_score_report(detections)

    return {
        "summary": {
            "total_detections": analytics_data.get("total_detections", 0),
            "behavioral_sequences": len(
                [d for d in detections if hasattr(d, "sequence")]
            ),
            "average_score": round(
                sum(item["score"] for item in score_data) / len(score_data),
                2,
            ) if score_data else 0,
        },
        "tactics": analytics_data.get("tactics", {}),
        "severity": analytics_data.get("severity", {}),
        "status": analytics_data.get("status", {}),
        "maturity": analytics_data.get("maturity_distribution", {}),
    }
