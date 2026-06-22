import os
import subprocess
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
from detlab.markdown_ingest import validate_markdown_detection_dir
from detlab.processing import (
    UnsupportedConversionTargetError,
    convert_detection_content,
    inspect_detection_content,
)
from detlab.scoring import generate_score_report
from detlab.sources import resolve_and_describe_detection_source, resolve_detection_dir
from detlab.templates import build_detection_templates
from detlab.validators import load_detection_dir

ROOT_PATH = os.getenv("DETLAB_ROOT_PATH", "")
REPO_ROOT = Path(__file__).resolve().parent.parent
MAX_DETECTION_REQUEST_BYTES = 25_000
ALLOWED_SAVE_ROOTS = ("detections", "knowledge")
ALLOWED_SAVE_SUFFIXES = {".yml", ".yaml", ".md"}

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


class DetectionSaveRequest(BaseModel):
    path: str = Field(..., min_length=1, max_length=256)
    content: str = Field(..., min_length=1, max_length=20000)


class RepoCommitRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=200)


def _load_detections(path: str):
    return load_detections(str(resolve_detection_dir(path)))


def _resolve_repo_save_path(relative_path: str) -> tuple[str, Path]:
    normalized = relative_path.strip().replace('\\', '/')
    candidate = Path(normalized)

    if (
        not normalized
        or candidate.is_absolute()
        or '..' in candidate.parts
        or candidate.parts[0] not in ALLOWED_SAVE_ROOTS
        or candidate.suffix.lower() not in ALLOWED_SAVE_SUFFIXES
    ):
        raise HTTPException(
            status_code=400,
            detail='Save path must stay within the DetLab repo and use detections/ or knowledge/',
        )

    resolved = (REPO_ROOT / candidate).resolve()
    try:
        resolved.relative_to(REPO_ROOT.resolve())
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail='Save path must stay within the DetLab repo and use detections/ or knowledge/',
        ) from exc

    return candidate.as_posix(), resolved


def _save_repo_content(relative_path: str, content: str) -> dict:
    inspection = inspect_detection_content(content)
    if not inspection['valid']:
        return inspection

    normalized_path, resolved_path = _resolve_repo_save_path(relative_path)
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_path.write_text(content.rstrip() + '\n', encoding='utf-8')

    return {
        'saved': True,
        'path': normalized_path,
        'repo_root': str(REPO_ROOT),
        'source_format': inspection.get('source_format'),
        'normalized_from': inspection.get('normalized_from'),
        'canonical_model_version': inspection.get('canonical_model_version'),
        'detection': inspection.get('detection'),
        'score': inspection.get('score'),
    }


def _normalize_content_index_key(content_kind: str) -> str:
    normalized = str(content_kind or 'investigation').strip().lower().replace('-', '_')
    if normalized == 'hunt':
        return 'hunts'
    if normalized in {'investigation', 'incident_response'}:
        return 'investigations'
    if normalized in {'forensics', 'forensic', 'artifact'}:
        return 'forensics'
    if normalized in {'learning_path', 'lab'}:
        return 'learning_paths'
    return 'investigations'


def _build_content_indexes(path: str = 'knowledge') -> dict:
    catalog = build_detection_catalog(path)
    indexes = {
        'hunts': {
            'slug': 'threat-hunts',
            'title': 'Threat Hunts',
            'description': 'Hypothesis-driven hunts, pivots, and follow-on detections.',
            'count': 0,
            'items': [],
        },
        'investigations': {
            'slug': 'investigations',
            'title': 'Investigations',
            'description': 'Incident response narratives, cloud case studies, and investigative writeups.',
            'count': 0,
            'items': [],
        },
        'forensics': {
            'slug': 'forensic-writeups',
            'title': 'Forensic Writeups',
            'description': 'Artifact-centric DFIR notes, timelines, and evidence handling guides.',
            'count': 0,
            'items': [],
        },
        'learning_paths': {
            'slug': 'learning-paths',
            'title': 'Learning Paths',
            'description': 'Structured labs, study tracks, and reusable learning artifacts.',
            'count': 0,
            'items': [],
        },
    }

    for detection in catalog['detections']:
        bucket = indexes[_normalize_content_index_key(detection.get('content_kind', ''))]
        item = {
            'id': detection['id'],
            'name': detection['name'],
            'title': detection['title'],
            'description': detection['description'],
            'severity': detection['severity'],
            'status': detection['status'],
            'content_kind': detection['content_kind'],
            'path': str(detection.get('path') or ''),
            'domain': detection['domain'],
            'platforms': detection['platforms'],
            'attack_techniques': detection['attack_techniques'],
        }
        bucket['items'].append(item)

    for bucket in indexes.values():
        bucket['items'] = sorted(bucket['items'], key=lambda item: (item['name'], item['id']))
        bucket['count'] = len(bucket['items'])

    return {
        'schema_version': catalog['schema_version'],
        'total': sum(bucket['count'] for bucket in indexes.values()),
        'indexes': indexes,
    }


def _run_git(*args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ['git', *args],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or 'Git command failed'
        raise HTTPException(status_code=400, detail=detail) from exc


def _get_repo_branch() -> str:
    return _run_git('symbolic-ref', '--short', 'HEAD').stdout.strip()


def _get_repo_changed_files() -> list[dict[str, str]]:
    output = _run_git('status', '--short', '--untracked-files=all').stdout.splitlines()
    changed_files = []
    for line in output:
        if not line.strip():
            continue
        changed_files.append(
            {
                'status': line[:2].strip() or '??',
                'path': line[3:].strip(),
            }
        )
    return changed_files


def _build_repo_status() -> dict:
    changed_files = _get_repo_changed_files()
    return {
        'branch': _get_repo_branch(),
        'clean': len(changed_files) == 0,
        'changed_files': changed_files,
    }


def _get_repo_staged_files() -> list[dict[str, str]]:
    output = _run_git('diff', '--cached', '--name-status').stdout.splitlines()
    staged_files = []
    for line in output:
        if not line.strip():
            continue
        parts = line.split('\t', 1)
        status = parts[0].strip() if parts else 'M'
        path = parts[1].strip() if len(parts) > 1 else ''
        staged_files.append({'status': status, 'path': path})
    return staged_files


def _repo_diff(relative_path: str | None = None) -> dict:
    args = ['diff', '--', relative_path] if relative_path else ['diff']
    diff_output = _run_git(*args).stdout
    return {
        'path': relative_path,
        'diff': diff_output,
        **_build_repo_status(),
    }


def _repo_commit(message: str) -> dict:
    commit_message = message.strip()
    if not commit_message:
        raise HTTPException(status_code=400, detail='Commit message cannot be empty')

    changed_files = _get_repo_changed_files()
    if not changed_files:
        raise HTTPException(status_code=400, detail='No repo changes to commit')

    _run_git('add', '-A')
    staged_files = _get_repo_staged_files()
    _run_git('commit', '-m', commit_message)
    commit = _run_git('rev-parse', 'HEAD').stdout.strip()
    return {
        'committed': True,
        'message': commit_message,
        'commit': commit,
        'branch': _get_repo_branch(),
        'changed_files': staged_files,
    }


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
    resolved_path, source_status = resolve_and_describe_detection_source(path)
    yaml_files, yaml_valid, yaml_errors = load_detection_dir(Path(resolved_path))
    markdown_files, markdown_valid, markdown_errors = validate_markdown_detection_dir(resolved_path)
    files = sorted({*yaml_files, *markdown_files})
    valid = yaml_valid and markdown_valid
    errors = {**yaml_errors, **markdown_errors}
    detections = load_detections(str(resolved_path))
    analytics_data = generate_analytics(detections)
    score_data = generate_score_report(detections)

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
    resolved_path = resolve_detection_dir(path)
    yaml_files, yaml_valid, yaml_errors = load_detection_dir(Path(resolved_path))
    markdown_files, markdown_valid, markdown_errors = validate_markdown_detection_dir(resolved_path)
    files = sorted({*yaml_files, *markdown_files})
    errors = {**yaml_errors, **markdown_errors}

    return {
        "valid": yaml_valid and markdown_valid,
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
    _, source_status = resolve_and_describe_detection_source(path)
    return source_status


@app.get("/dashboard")
def dashboard(path: str = "detections"):
    return _build_dashboard_payload(path)


@app.get("/schema/domain")
def domain_schema():
    return export_domain_schema()


@app.get("/detections/catalog")
def detection_catalog(path: str = "detections"):
    return build_detection_catalog(path)


@app.get('/content/indexes')
def content_indexes(path: str = 'knowledge'):
    return _build_content_indexes(path)


@app.get("/detections/templates")
def detection_templates():
    return build_detection_templates()


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


@app.post("/detections/save")
def save_detection(request: DetectionSaveRequest):
    result = _save_repo_content(request.path, request.content)
    if result.get('saved'):
        return result
    return JSONResponse(status_code=422, content=result)


@app.get('/repo/status')
def repo_status():
    return _build_repo_status()


@app.get('/repo/diff')
def repo_diff(path: str | None = None):
    return _repo_diff(path)


@app.post('/repo/commit')
def repo_commit(request: RepoCommitRequest):
    return _repo_commit(request.message)
