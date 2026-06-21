from pathlib import Path
from typing import Any

from detlab.contracts import CANONICAL_MODEL_VERSION
from detlab.eql import export_eql_detection
from detlab.kql import export_kql_detection
from detlab.markdown_ingest import load_markdown_detections
from detlab.sigma_export import export_sigma_detection
from detlab.splunk import export_splunk_detection
from detlab.models import (
    ArtifactReference,
    AttackContext,
    CloudTelemetryReference,
    DataSource,
    Detection,
    HuntSuggestion,
    InvestigationStep,
    RelatedDetection,
    ResponseAction,
)
from detlab.sources import resolve_detection_dir
from detlab.validators import load_detection_file


def load_detections(path: str = "detections") -> list[Detection]:
    detection_dir = resolve_detection_dir(path)
    yaml_files = sorted(Path(detection_dir).rglob("*.y*ml"))
    detections = []
    for file_path in yaml_files:
        detection = load_detection_file(file_path)
        relative_path = str(file_path.relative_to(detection_dir))
        detection.detection.selection.setdefault("SourcePath", relative_path)
        detection.detection.selection.setdefault("SourceFormat", "yaml")
        detection.detection.selection.setdefault("NormalizedFrom", "canonical_yaml")
        detections.append(detection)
    detections.extend(load_markdown_detections(detection_dir))
    return detections



def _render_conversions(detection: Detection) -> dict[str, str]:
    renderable = detection.model_copy(deep=True)
    renderable.detection.selection.pop("SourcePath", None)
    renderable.detection.selection.pop("SourceFormat", None)
    renderable.detection.selection.pop("NormalizedFrom", None)
    return {
        "sigma": export_sigma_detection(renderable),
        "splunk": export_splunk_detection(renderable),
        "kql": export_kql_detection(renderable),
        "eql": export_eql_detection(renderable),
    }



def _workspace_normalization_metadata(detection: Detection) -> dict[str, str]:
    selection = detection.detection.selection
    source_path = str(selection.get("SourcePath") or "")
    source_format = str(selection.get("SourceFormat") or ("markdown" if source_path.endswith(".md") else "yaml"))
    normalized_from = str(selection.get("NormalizedFrom") or ("markdown_frontmatter" if source_format == "markdown" else "canonical_yaml"))
    return {
        "source_format": source_format,
        "normalized_from": normalized_from,
        "canonical_model_version": CANONICAL_MODEL_VERSION,
    }



def export_domain_schema() -> dict[str, Any]:
    return {
        "schema_version": CANONICAL_MODEL_VERSION,
        "primary_entity": "Detection",
        "entities": {
            "Detection": Detection.model_json_schema(),
            "AttackContext": AttackContext.model_json_schema(),
            "DataSource": DataSource.model_json_schema(),
            "InvestigationStep": InvestigationStep.model_json_schema(),
            "HuntSuggestion": HuntSuggestion.model_json_schema(),
            "ArtifactReference": ArtifactReference.model_json_schema(),
            "CloudTelemetryReference": CloudTelemetryReference.model_json_schema(),
            "RelatedDetection": RelatedDetection.model_json_schema(),
            "ResponseAction": ResponseAction.model_json_schema(),
        },
    }


def _infer_domain(detection: Detection) -> list[str]:
    if detection.domain:
        return [str(item) for item in detection.domain]

    product = detection.logsource.product.lower()
    if product in {"aws", "azure", "gcp"}:
        return ["cloud"]
    if product in {"okta", "entra", "identity"}:
        return ["identity"]
    return ["endpoint"]


def _infer_platforms(detection: Detection) -> list[str]:
    return detection.platforms or [detection.logsource.product]


def _default_data_sources(detection: Detection) -> list[dict[str, Any]]:
    if detection.data_sources:
        return [item.model_dump() for item in detection.data_sources]
    return [
        {
            "name": f"{detection.logsource.product}:{detection.logsource.service}",
            "kind": "endpoint" if "cloud" not in _infer_domain(detection) else "cloud",
            "provider": detection.logsource.product,
            "event_names": [],
            "notes": "Derived from detection logsource because curated data_sources are not populated yet.",
        }
    ]


def _default_triage_steps(detection: Detection) -> list[dict[str, Any]]:
    if detection.triage_steps:
        return [step.model_dump() for step in detection.triage_steps]
    return [
        {
            "step": "Validate the originating host, user, process tree, and full command line.",
            "priority": "high",
            "rationale": "Establish whether the alert reflects expected administration or suspicious execution.",
        },
        {
            "step": "Scope for nearby executions with the same parent process, image path, or selector values.",
            "priority": "high",
            "rationale": "Determine whether the activity is isolated or part of a broader sequence.",
        },
    ]


def _default_investigation_steps(detection: Detection) -> list[dict[str, Any]]:
    if detection.investigation_steps:
        return [step.model_dump() for step in detection.investigation_steps]
    return [
        {
            "step": "Collect supporting event logs, command-line telemetry, and process ancestry for the triggering execution.",
            "priority": "high",
            "rationale": "Support validation and scoping of the detection.",
        }
    ]


def _attack_map(detection: Detection) -> dict[str, list[dict[str, Any]]]:
    direct = [
        {
            "technique": detection.attack.technique,
            "tactic": detection.attack.tactic,
            "name": detection.title,
            "coverage": "direct",
            "rationale": "Primary ATT&CK mapping declared by the detection.",
        }
    ]
    grouped = {"direct": direct, "partial": [], "related": [], "gap": []}
    for item in detection.attack_context:
        grouped[item.coverage].append(item.model_dump())
    return grouped


def _relationship_entries(detection: Detection, all_detections: list[Detection]) -> list[dict[str, Any]]:
    index = {item.id: item for item in all_detections}
    related = []
    for relation in detection.related_detections:
        target = index.get(relation.detection_id)
        related.append(
            {
                "detection_id": relation.detection_id,
                "title": target.title if target else relation.detection_id,
                "severity": target.severity if target else None,
                "status": target.status if target else None,
                "relationship": relation.relationship,
                "rationale": relation.rationale,
            }
        )

    if related:
        return related

    inferred = []
    for candidate in all_detections:
        if candidate.id == detection.id:
            continue
        if candidate.attack.technique == detection.attack.technique:
            inferred.append(
                {
                    "detection_id": candidate.id,
                    "title": candidate.title,
                    "severity": candidate.severity,
                    "status": candidate.status,
                    "relationship": "similar",
                    "rationale": "Inferred because both detections share the same primary ATT&CK technique.",
                }
            )
        elif candidate.logsource.product == detection.logsource.product:
            inferred.append(
                {
                    "detection_id": candidate.id,
                    "title": candidate.title,
                    "severity": candidate.severity,
                    "status": candidate.status,
                    "relationship": "correlated",
                    "rationale": "Inferred because both detections rely on the same platform telemetry.",
                }
            )
    return inferred[:5]


def _relationship_graph(detection: Detection, all_detections: list[Detection]) -> dict[str, list[dict[str, Any]]]:
    related = _relationship_entries(detection, all_detections)
    nodes: list[dict[str, Any]] = [
        {
            "id": detection.id,
            "label": detection.title,
            "kind": "selected_detection",
            "severity": detection.severity,
        }
    ]
    edges: list[dict[str, Any]] = []
    for item in related:
        nodes.append(
            {
                "id": item["detection_id"],
                "label": item["title"],
                "kind": "related_detection",
                "severity": item.get("severity"),
            }
        )
        edges.append(
            {
                "source": detection.id,
                "target": item["detection_id"],
                "relationship": item["relationship"],
                "rationale": item.get("rationale"),
            }
        )
    return {"nodes": nodes, "edges": edges}


def _knowledge_gaps(detection: Detection) -> list[str]:
    gaps = []
    if not detection.attack_context:
        gaps.append("No secondary ATT&CK coverage context is curated yet.")
    if not detection.artifacts:
        gaps.append("No DFIR artifact guidance is curated yet.")
    if not detection.hunt_suggestions:
        gaps.append("No related hunt hypotheses are curated yet.")
    if not detection.cloud_telemetry:
        gaps.append("No cloud telemetry pivots are curated yet.")
    if not detection.related_detections:
        gaps.append("No explicit related detection graph edges are curated yet.")
    return gaps


def build_detection_catalog(path: str = "detections") -> dict[str, Any]:
    detections = load_detections(path)
    entries = []
    for detection in detections:
        readiness_signals = [
            bool(detection.triage_steps),
            bool(detection.investigation_steps),
            bool(detection.artifacts),
            bool(detection.related_detections),
            bool(detection.hunt_suggestions),
            bool(detection.cloud_telemetry),
        ]
        readiness_score = round(sum(1 for signal in readiness_signals if signal) / len(readiness_signals) * 100)
        entries.append(
            {
                "id": detection.id,
                "name": detection.name or detection.title,
                "title": detection.title,
                "description": detection.description,
                "severity": detection.severity,
                "status": detection.status,
                "domain": _infer_domain(detection),
                "platforms": _infer_platforms(detection),
                "attack_techniques": [detection.attack.technique],
                "data_sources": [item["name"] for item in _default_data_sources(detection)],
                "related_detections_count": len(_relationship_entries(detection, detections)),
                "investigation_readiness_score": readiness_score,
            }
        )

    return {
        "schema_version": CANONICAL_MODEL_VERSION,
        "total": len(entries),
        "detections": sorted(entries, key=lambda item: (item["name"], item["id"])),
    }


def build_detection_workspace(detection_id: str, path: str = "detections") -> dict[str, Any] | None:
    detections = load_detections(path)
    index = {detection.id: detection for detection in detections}
    detection = index.get(detection_id)
    if detection is None:
        return None

    attack_map = _attack_map(detection)
    related = _relationship_entries(detection, detections)
    metadata = _workspace_normalization_metadata(detection)

    return {
        "schema_version": CANONICAL_MODEL_VERSION,
        "source_format": metadata["source_format"],
        "normalized_from": metadata["normalized_from"],
        "canonical_model_version": metadata["canonical_model_version"],
        "detection": {
            "id": detection.id,
            "name": detection.name or detection.title,
            "title": detection.title,
            "description": detection.description,
            "severity": detection.severity,
            "status": detection.status,
            "author": detection.author,
            "domain": _infer_domain(detection),
            "platforms": _infer_platforms(detection),
        },
        "overview": {
            "purpose": detection.description,
            "attack_mappings": {
                "primary": detection.attack.model_dump(),
                "context": [item.model_dump() for item in detection.attack_context],
            },
            "data_sources": _default_data_sources(detection),
            "content_source": {
                "path": detection.detection.selection.get("SourcePath"),
                "kind": detection.detection.selection.get("ContentKind"),
            },
            "query": {
                "language": detection.detection.selection.get("QueryLanguage"),
                "text": detection.detection.selection.get("QueryText"),
            },
            "detection_logic": detection.detection.model_dump(),
            "references": detection.references,
        },
        "investigation_guidance": {
            "triage_steps": _default_triage_steps(detection),
            "investigation_steps": _default_investigation_steps(detection),
            "escalation_guidance": detection.escalation_guidance,
            "false_positives": detection.falsepositives,
        },
        "threat_hunting": {
            "related_hunts": [hunt.model_dump() for hunt in detection.hunt_suggestions],
            "related_detections": related,
            "adjacent_techniques": attack_map["related"],
            "coverage_gaps": attack_map["gap"],
        },
        "dfir_guidance": {
            "artifacts": [artifact.model_dump() for artifact in detection.artifacts],
            "velociraptor_artifacts": detection.velociraptor_artifacts,
        },
        "cloud_security": {
            "telemetry": [item.model_dump() for item in detection.cloud_telemetry],
        },
        "response_actions": [action.model_dump() for action in detection.response_actions],
        "related_detections": related,
        "heat_map": attack_map,
        "relationship_graph": _relationship_graph(detection, detections),
        "knowledge_gaps": _knowledge_gaps(detection),
        "conversions": _render_conversions(detection),
    }
