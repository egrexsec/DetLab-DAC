from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, cast

import yaml

from detlab.models import (
    ArtifactReference,
    Attack,
    AttackContext,
    CloudTelemetryReference,
    DataSource,
    Detection,
    DetectionLogic,
    HuntSuggestion,
    InvestigationStep,
    LogSource,
    RelatedDetection,
    ResponseAction,
    TestRef,
)
from detlab.sources import DetectionSource, source_from_environment

ATTACK_INLINE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
HEADING_RE = re.compile(r"^##\s+(?P<title>.+)$", re.MULTILINE)
TACTIC_KEYWORDS = {
    "initial access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege escalation": "privilege-escalation",
    "defense evasion": "defense-evasion",
    "credential access": "credential-access",
    "discovery": "discovery",
    "lateral movement": "lateral-movement",
    "collection": "collection",
    "command and control": "command-and-control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}


SECTION_ALIASES = {
    "data_sources": {
        "focus areas",
        "data tables",
        "data sources",
        "environment",
        "aws services",
        "tools used",
        "cloud evidence",
        "cloudtrail analysis",
        "iam analysis",
        "s3 analysis",
    },
    "triage_steps": {
        "triage guidance",
        "triage",
        "initial alert",
        "objective",
        "hunt hypothesis",
        "discovery process",
        "initial indicators",
    },
    "investigation_steps": {
        "investigation steps",
        "investigation workflow",
        "investigation process",
        "analysis",
        "evidence collected",
        "timeline",
        "detection opportunities",
        "investigative value",
        "walkthrough",
        "findings",
        "lessons learned",
        "real-world application",
        "detection engineering opportunities",
        "threat hunting opportunities",
        "response workflow",
    },
    "falsepositives": {"false positives", "mistakes made", "common misconfigurations"},
    "artifacts": {
        "evidence collected",
        "important fields",
        "artifacts",
        "evidence",
        "logs",
        "cloud evidence",
    },
    "response_actions": {
        "containment actions",
        "response actions",
        "incident response actions",
        "eradication actions",
        "recovery actions",
        "defensive recommendations",
        "defensive improvements",
        "recommendations",
    },
    "escalation_guidance": {
        "lessons learned",
        "root cause",
        "root cause analysis",
        "impact assessment",
        "future detection opportunities",
        "follow-up hunts",
        "defensive recommendations",
        "best practices",
        "key exam concepts",
    },
    "velociraptor_artifacts": {"velociraptor artifacts"},
    "related_detections": {"related detections", "detection opportunities", "future detection opportunities"},
    "related_hunts": {"related hunts", "threat hunting opportunities", "follow-up hunts"},
    "cloud_telemetry": {
        "cloud telemetry",
        "logs reviewed",
        "aws services used",
        "investigation workflow",
        "cloudtrail analysis",
        "iam analysis",
        "s3 analysis",
        "real-world usage",
    },
}


def load_markdown_detections(path: str | Path) -> list[Detection]:
    root = Path(path)
    files = sorted(file_path for file_path in root.rglob("*.md") if file_path.is_file())
    used_ids: set[str] = set()
    detections: list[Detection] = []
    source = source_from_environment()

    for file_path in files:
        detection = _markdown_file_to_detection(file_path, root, source, used_ids)
        if detection is not None:
            detections.append(detection)

    return detections



def markdown_source_files(path: str | Path) -> list[Path]:
    root = Path(path)
    return sorted(file_path for file_path in root.rglob("*.md") if file_path.is_file())



def validate_markdown_detection_dir(path: str | Path) -> tuple[list[Path], bool, dict[Path, str]]:
    root = Path(path)
    source = source_from_environment()
    used_ids: set[str] = set()
    files: list[Path] = []
    errors: dict[Path, str] = {}

    for file_path in markdown_source_files(root):
        raw_text = file_path.read_text(encoding="utf-8")
        frontmatter, body = _split_frontmatter(raw_text)
        sections = _extract_sections(body)
        _, query_text = _extract_query_block(sections)
        if _should_skip_markdown_file(file_path, frontmatter, sections, query_text):
            continue
        files.append(file_path)
        try:
            detection = _markdown_file_to_detection(file_path, root, source, used_ids)
            if detection is None:
                errors[file_path] = "Markdown entry was skipped during ingestion."
        except Exception as exc:
            errors[file_path] = str(exc)

    return files, len(errors) == 0, errors



def _markdown_file_to_detection(
    file_path: Path,
    root: Path,
    source: DetectionSource | None,
    used_ids: set[str],
) -> Detection | None:
    raw_text = file_path.read_text(encoding="utf-8")
    relative_path = file_path.relative_to(root).as_posix()
    return _markdown_text_to_detection(raw_text, file_path, relative_path, source, used_ids)



def parse_markdown_detection_content(
    content: str,
    *,
    relative_path: str = "inline.md",
    source: DetectionSource | None = None,
    used_ids: set[str] | None = None,
) -> Detection | None:
    pseudo_path = Path(relative_path)
    return _markdown_text_to_detection(content, pseudo_path, relative_path, source, used_ids or set())



def _markdown_text_to_detection(
    raw_text: str,
    file_path: Path,
    relative_path: str,
    source: DetectionSource | None,
    used_ids: set[str],
) -> Detection | None:
    frontmatter, body = _split_frontmatter(raw_text)
    sections = _extract_sections(body)
    query_language, query_text = _extract_query_block(sections)
    if _should_skip_markdown_file(file_path, frontmatter, sections, query_text):
        return None
    title = str(frontmatter.get("title") or frontmatter.get("name") or _extract_title(body, file_path))
    description = (
        str(frontmatter.get("description"))
        if frontmatter.get("description")
        else _extract_description(body, sections)
        or f"Markdown knowledge entry ingested from {relative_path}."
    )

    default_product, default_service, default_domain, default_platforms = _infer_source_attributes(file_path)
    raw_logsource = frontmatter.get("logsource")
    raw_attack = frontmatter.get("attack")
    logsource_payload: dict[str, Any] = raw_logsource if isinstance(raw_logsource, dict) else {}
    attack_payload: dict[str, Any] = raw_attack if isinstance(raw_attack, dict) else {}

    inline_attack_ids = ATTACK_INLINE_RE.findall(raw_text)
    primary_technique = str(attack_payload.get("technique") or frontmatter.get("attack_technique") or (inline_attack_ids[0] if inline_attack_ids else "T0000"))
    primary_tactic = str(
        attack_payload.get("tactic")
        or frontmatter.get("attack_tactic")
        or _infer_tactic(raw_text)
        or _infer_tactic_from_path(file_path)
        or "unknown"
    )

    data_source_items = _coerce_data_sources(frontmatter.get("data_sources"), default_product)
    if not data_source_items:
        focus_items = _collect_list_items(sections, SECTION_ALIASES["data_sources"])
        focus_items.extend(_extract_labeled_bullets(body, "Focus Areas"))
        focus_items = list(dict.fromkeys(focus_items))
        data_source_items = _build_data_sources_from_names(focus_items, default_product)

    triage_steps = _coerce_steps(frontmatter.get("triage_steps"))
    if not triage_steps:
        triage_steps = _coerce_steps(_collect_list_items(sections, SECTION_ALIASES["triage_steps"]))

    investigation_steps = _coerce_steps(frontmatter.get("investigation_steps"))
    if not investigation_steps:
        investigation_steps = _coerce_steps(_collect_list_items(sections, SECTION_ALIASES["investigation_steps"]))

    escalation_guidance = _coerce_strings(frontmatter.get("escalation_guidance"))
    if not escalation_guidance:
        escalation_guidance = _collect_list_items(sections, SECTION_ALIASES["escalation_guidance"])

    false_positives = _coerce_strings(frontmatter.get("falsepositives") or frontmatter.get("false_positives"))
    if not false_positives:
        false_positives = _collect_list_items(sections, SECTION_ALIASES["falsepositives"])

    artifacts = _coerce_artifacts(frontmatter.get("artifacts"))
    if not artifacts:
        artifacts = _coerce_artifacts(_collect_list_items(sections, SECTION_ALIASES["artifacts"]))

    response_actions = _coerce_response_actions(frontmatter.get("response_actions"))
    if not response_actions:
        response_actions = _coerce_response_actions(_collect_list_items(sections, SECTION_ALIASES["response_actions"]))

    hunt_suggestions = _coerce_hunts(frontmatter.get("hunt_suggestions") or frontmatter.get("related_hunts"))
    if not hunt_suggestions:
        hunt_suggestions = _coerce_hunts(_collect_list_items(sections, SECTION_ALIASES["related_hunts"]))
    if not hunt_suggestions and query_text:
        hunt_suggestions = [
            HuntSuggestion(
                name=f"{title} follow-on hunt",
                hypothesis="Expand the imported markdown logic into broader scoping and adjacent activity review.",
                query_hint=query_text[:500],
            )
        ]

    velociraptor_artifacts = _coerce_strings(frontmatter.get("velociraptor_artifacts"))
    if not velociraptor_artifacts:
        velociraptor_artifacts = _collect_list_items(sections, SECTION_ALIASES["velociraptor_artifacts"])
    if not velociraptor_artifacts and "velociraptor" in [part.lower() for part in file_path.parts]:
        velociraptor_artifacts = [_extract_title(body, file_path)]

    cloud_telemetry = _coerce_cloud_telemetry(frontmatter.get("cloud_telemetry"))
    if not cloud_telemetry and "aws" in [part.lower() for part in file_path.parts]:
        cloud_items = _collect_list_items(sections, SECTION_ALIASES["cloud_telemetry"])
        cloud_telemetry = [
            CloudTelemetryReference(
                provider="aws",
                source="CloudTrail",
                event_names=cloud_items,
                notes="Derived from markdown cloud investigation content.",
            )
        ]

    related_detections = _coerce_related_detections(frontmatter.get("related_detections"))
    tests = _coerce_tests(frontmatter.get("tests"), relative_path)
    references = _build_references(relative_path, source, frontmatter)
    attack_context = _coerce_attack_context(frontmatter.get("attack_context"))
    if not attack_context:
        attack_context = _build_attack_context_from_inline_ids(inline_attack_ids[1:])

    content_kind = str(frontmatter.get("content_kind") or frontmatter.get("kind") or _infer_content_kind(file_path))
    detection_id = _resolve_detection_id(frontmatter.get("id"), relative_path, used_ids)

    return Detection(
        id=detection_id,
        title=title,
        name=str(frontmatter.get("name") or title),
        description=description,
        logsource=LogSource(
            product=str(logsource_payload.get("product") or default_product),
            service=str(logsource_payload.get("service") or default_service),
        ),
        attack=Attack(technique=primary_technique, tactic=primary_tactic),
        severity=str(frontmatter.get("severity") or _default_severity(file_path)),
        status=str(frontmatter.get("status") or "draft"),
        author=str(frontmatter.get("author") or "markdown-ingest"),
        domain=cast(Any, _coerce_domain(frontmatter.get("domain"), default_domain)),
        platforms=_coerce_strings(frontmatter.get("platforms")) or default_platforms,
        references=references,
        falsepositives=false_positives,
        tests=tests,
        detection=DetectionLogic(
            selection=_build_selection(relative_path, query_text, query_language, content_kind),
            condition="selection",
        ),
        attack_context=attack_context,
        data_sources=data_source_items,
        triage_steps=triage_steps,
        investigation_steps=investigation_steps,
        escalation_guidance=escalation_guidance,
        hunt_suggestions=hunt_suggestions,
        artifacts=artifacts,
        velociraptor_artifacts=velociraptor_artifacts,
        cloud_telemetry=cloud_telemetry,
        related_detections=related_detections,
        response_actions=response_actions,
    )



def _split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end == -1:
        return {}, text
    raw_frontmatter = text[4:end]
    try:
        parsed = yaml.safe_load(raw_frontmatter) or {}
    except yaml.YAMLError:
        parsed = {}
    return parsed if isinstance(parsed, dict) else {}, text[end + 5 :]



def _extract_title(body: str, file_path: Path) -> str:
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return file_path.stem.replace("-", " ").replace("_", " ").title()



def _extract_sections(body: str) -> dict[str, str]:
    matches = list(HEADING_RE.finditer(body))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        sections[match.group("title").strip().lower()] = body[start:end].strip()
    return sections



def _extract_description(body: str, sections: dict[str, str]) -> str:
    lines = [line.strip() for line in body.splitlines()]
    collected: list[str] = []
    after_title = False
    for line in lines:
        if line.startswith("# "):
            after_title = True
            continue
        if not after_title:
            continue
        if line.startswith("## "):
            break
        if not line:
            if collected:
                break
            continue
        if line.endswith(":") and not collected:
            continue
        if line.startswith(("- ", "* ")):
            continue
        collected.append(line)
    if collected:
        return " ".join(collected).strip()
    if sections.get("scenario"):
        return sections["scenario"].splitlines()[0].strip()
    if sections.get("objective"):
        return sections["objective"].splitlines()[0].strip()
    if sections.get("purpose"):
        return sections["purpose"].splitlines()[0].strip()
    return ""



def _extract_query_block(sections: dict[str, str]) -> tuple[str | None, str | None]:
    for key in ("query", "queries", "detection logic", "hunt methodology"):
        content = sections.get(key)
        if not content:
            continue
        match = re.search(r"```(?P<lang>\w+)?\n(?P<body>.*?)```", content, re.DOTALL)
        if match:
            language = match.group("lang") or None
            query = match.group("body").strip()
            return language, query
        stripped = content.strip()
        if stripped:
            return None, stripped
    return None, None



def _should_skip_markdown_file(
    file_path: Path,
    frontmatter: dict[str, Any],
    sections: dict[str, str],
    query_text: str | None,
) -> bool:
    if frontmatter.get("id") or frontmatter.get("attack") or frontmatter.get("attack_technique"):
        return False
    if query_text:
        return False
    if any(
        key in sections
        for key in (
            "triage guidance",
            "investigation steps",
            "artifacts",
            "false positives",
            "hunt hypothesis",
            "walkthrough",
            "evidence collected",
        )
    ):
        return False
    return file_path.name.lower() == "readme.md"



def _infer_tactic(text: str) -> str | None:
    lowered = text.lower()
    for keyword, tactic in TACTIC_KEYWORDS.items():
        if keyword in lowered:
            return tactic
    return None



def _infer_tactic_from_path(file_path: Path) -> str | None:
    lowered_parts = " ".join(part.lower() for part in file_path.parts)
    return _infer_tactic(lowered_parts)



def _infer_source_attributes(file_path: Path) -> tuple[str, str, list[str], list[str]]:
    lowered = [part.lower() for part in file_path.parts]
    if "flaws-cloud" in lowered or "flaws2-cloud" in lowered:
        return "aws", "cloudtrail", ["cloud"], ["aws"]
    if "aws" in lowered:
        return "aws", "cloudtrail", ["cloud"], ["aws"]
    if "learning-paths" in lowered:
        return "markdown", "learning_path", ["endpoint"], ["markdown"]
    if "labs" in lowered:
        return "markdown", "lab", ["endpoint"], ["markdown"]
    if "incident-response" in lowered or "incident-response-case-studies" in lowered:
        return "markdown", "incident_response", ["endpoint"], ["markdown"]
    if "threat-hunts" in lowered:
        return "markdown", "threat_hunt", ["endpoint"], ["markdown"]
    if "detection-engineering" in lowered:
        return "markdown", "detection_engineering", ["endpoint"], ["markdown"]
    if "velociraptor" in lowered:
        return "windows", "velociraptor", ["endpoint"], ["windows"]
    if "mde" in lowered:
        return "mde", "advanced_hunting", ["endpoint"], ["windows", "mde"]
    return "markdown", "knowledge_base", ["endpoint"], ["markdown"]



def _infer_content_kind(file_path: Path) -> str:
    lowered = [part.lower() for part in file_path.parts]
    if "learning-paths" in lowered:
        return "learning_path"
    if "labs" in lowered:
        return "lab"
    if "incident-response" in lowered or "incident-response-case-studies" in lowered:
        return "incident_response"
    if "forensics" in lowered:
        return "forensics"
    if "threat-hunts" in lowered:
        return "hunt"
    if "detection-engineering" in lowered:
        return "detection"
    if "aws-security-learning" in lowered:
        return "learning_path"
    if "flaws-cloud" in lowered or "flaws2-cloud" in lowered:
        return "investigation"
    if "velociraptor" in lowered:
        return "artifact"
    if "aws" in lowered:
        return "investigation"
    return "hunt"



def _default_severity(file_path: Path) -> str:
    lowered = "/".join(part.lower() for part in file_path.parts)
    if "aws" in lowered:
        return "medium"
    if "velociraptor" in lowered:
        return "high"
    return "medium"



def _resolve_detection_id(raw_id: Any, relative_path: str, used_ids: set[str]) -> str:
    if isinstance(raw_id, str) and raw_id.startswith("DET-"):
        if raw_id in used_ids:
            raise ValueError(f"Duplicate markdown detection id: {raw_id}")
        used_ids.add(raw_id)
        return raw_id
    digest = hashlib.sha1(relative_path.encode("utf-8")).hexdigest()
    candidate = 1000 + (int(digest[:8], 16) % 9000)
    detection_id = f"DET-{candidate:04d}"
    while detection_id in used_ids:
        candidate = 1000 + ((candidate - 999) % 9000)
        detection_id = f"DET-{candidate:04d}"
    used_ids.add(detection_id)
    return detection_id



def _build_references(relative_path: str, source: DetectionSource | None, frontmatter: dict[str, Any]) -> list[str]:
    references = _coerce_strings(frontmatter.get("references"))
    if source and source.repo_url and source.ref and source.subdir:
        repo_url = source.repo_url[:-4] if source.repo_url.endswith(".git") else source.repo_url
        references.append(f"{repo_url}/blob/{source.ref}/{source.subdir.rstrip('/')}/{relative_path}")
    else:
        references.append(relative_path)
    return list(dict.fromkeys(references))



def _collect_list_items(sections: dict[str, str], keys: set[str]) -> list[str]:
    items: list[str] = []
    for key in keys:
        content = sections.get(key)
        if not content:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith(("- ", "* ")):
                items.append(stripped[2:].strip())
    return items



def _extract_labeled_bullets(body: str, label: str) -> list[str]:
    items: list[str] = []
    collecting = False
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.lower() == f"{label.lower()}:":
            collecting = True
            continue
        if not collecting:
            continue
        if stripped.startswith("## "):
            break
        if stripped.startswith(("- ", "* ")):
            items.append(stripped[2:].strip())
            continue
        if stripped and items:
            break
    return items



def _coerce_strings(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(item) for item in raw if item not in (None, "")]
    return [str(raw)]



def _coerce_domain(raw: Any, default_domain: list[str]) -> list[str]:
    allowed = {"endpoint", "identity", "cloud", "network", "email"}
    values = [item for item in _coerce_strings(raw) if item in allowed]
    return values or default_domain



def _coerce_data_sources(raw: Any, default_product: str) -> list[DataSource]:
    items: list[DataSource] = []
    if not raw:
        return items
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                items.append(
                    DataSource(
                        name=str(item.get("name") or item.get("table") or item.get("source") or "unknown"),
                        kind=cast(Any, str(item.get("kind") or "other")),
                        provider=str(item.get("provider") or default_product),
                        event_names=_coerce_strings(item.get("event_names")),
                        notes=str(item.get("notes")) if item.get("notes") else None,
                    )
                )
            else:
                items.append(DataSource(name=str(item), kind="other", provider=default_product))
    return items



def _build_data_sources_from_names(items: list[str], default_product: str) -> list[DataSource]:
    if not items:
        return [
            DataSource(
                name=f"{default_product}:markdown",
                kind="other",
                provider=default_product,
                notes="Derived from markdown knowledge source metadata.",
            )
        ]
    kind = "cloud" if default_product in {"aws", "azure", "gcp"} else "endpoint"
    return [DataSource(name=item, kind=kind, provider=default_product) for item in items]



def _coerce_steps(raw: Any) -> list[InvestigationStep]:
    items: list[InvestigationStep] = []
    if not raw:
        return items
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                items.append(
                    InvestigationStep(
                        step=str(item.get("step") or item.get("title") or ""),
                        priority=cast(Any, str(item.get("priority") or "medium")),
                        rationale=str(item.get("rationale")) if item.get("rationale") else None,
                    )
                )
            else:
                items.append(
                    InvestigationStep(
                        step=str(item),
                        priority="medium",
                        rationale="Imported from markdown knowledge content.",
                    )
                )
    return [item for item in items if item.step]



def _coerce_hunts(raw: Any) -> list[HuntSuggestion]:
    items: list[HuntSuggestion] = []
    if not raw:
        return items
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                items.append(
                    HuntSuggestion(
                        name=str(item.get("name") or item.get("title") or ""),
                        hypothesis=str(item.get("hypothesis")) if item.get("hypothesis") else None,
                        query_hint=str(item.get("query_hint")) if item.get("query_hint") else None,
                    )
                )
            else:
                items.append(HuntSuggestion(name=str(item)))
    return [item for item in items if item.name]



def _coerce_artifacts(raw: Any) -> list[ArtifactReference]:
    items: list[ArtifactReference] = []
    if not raw:
        return items
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                items.append(
                    ArtifactReference(
                        name=str(item.get("name") or item.get("field") or item.get("path") or "artifact"),
                        category=cast(Any, str(item.get("category") or "other")),
                        path=str(item.get("path")) if item.get("path") else None,
                        notes=str(item.get("notes")) if item.get("notes") else None,
                    )
                )
            else:
                items.append(
                    ArtifactReference(
                        name=str(item),
                        category="other",
                        notes="Imported from markdown evidence or artifact guidance.",
                    )
                )
    return items



def _coerce_cloud_telemetry(raw: Any) -> list[CloudTelemetryReference]:
    items: list[CloudTelemetryReference] = []
    if not raw:
        return items
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                items.append(
                    CloudTelemetryReference(
                        provider=cast(Any, str(item.get("provider") or "other")),
                        source=str(item.get("source") or "unknown"),
                        event_names=_coerce_strings(item.get("event_names")),
                        notes=str(item.get("notes")) if item.get("notes") else None,
                    )
                )
            else:
                items.append(
                    CloudTelemetryReference(
                        provider="other",
                        source=str(item),
                        event_names=[],
                        notes="Imported from markdown cloud telemetry guidance.",
                    )
                )
    return items



def _coerce_related_detections(raw: Any) -> list[RelatedDetection]:
    items: list[RelatedDetection] = []
    if not raw:
        return items
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                detection_id = item.get("detection_id") or item.get("id")
                if detection_id:
                    items.append(
                        RelatedDetection(
                            detection_id=str(detection_id),
                            relationship=cast(Any, str(item.get("relationship") or "correlated")),
                            rationale=str(item.get("rationale")) if item.get("rationale") else None,
                        )
                    )
    return items



def _coerce_response_actions(raw: Any) -> list[ResponseAction]:
    items: list[ResponseAction] = []
    if not raw:
        return items
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                title = item.get("title") or item.get("action")
                if title:
                    items.append(
                        ResponseAction(
                            title=str(title),
                            priority=cast(Any, str(item.get("priority") or "medium")),
                            description=str(item.get("description")) if item.get("description") else None,
                        )
                    )
            else:
                items.append(
                    ResponseAction(
                        title=str(item),
                        priority="medium",
                        description="Imported from markdown response guidance.",
                    )
                )
    return items



def _coerce_tests(raw: Any, relative_path: str) -> list[TestRef]:
    items: list[TestRef] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("name") and item.get("source") and item.get("test_id") is not None:
                items.append(
                    TestRef(
                        name=str(item["name"]),
                        source=str(item["source"]),
                        test_id=str(item["test_id"]),
                    )
                )
    if items:
        return items
    return [TestRef(name="Markdown knowledge import", source="markdown", test_id=relative_path)]



def _coerce_attack_context(raw: Any) -> list[AttackContext]:
    items: list[AttackContext] = []
    if not raw:
        return items
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and item.get("technique"):
                items.append(
                    AttackContext(
                        technique=str(item["technique"]),
                        tactic=str(item.get("tactic")) if item.get("tactic") else None,
                        name=str(item.get("name")) if item.get("name") else None,
                        coverage=cast(Any, str(item.get("coverage") or "related")),
                        rationale=str(item.get("rationale")) if item.get("rationale") else None,
                    )
                )
    return items



def _build_attack_context_from_inline_ids(attack_ids: list[str]) -> list[AttackContext]:
    return [
        AttackContext(
            technique=technique,
            tactic=None,
            name=None,
            coverage="related",
            rationale="Additional ATT&CK technique parsed from markdown knowledge content.",
        )
        for technique in dict.fromkeys(attack_ids)
    ]



def _build_selection(relative_path: str, query_text: str | None, query_language: str | None, content_kind: str) -> dict[str, str]:
    selection = {
        "SourcePath": relative_path,
        "ContentKind": content_kind,
        "SourceFormat": "markdown",
        "NormalizedFrom": "markdown_frontmatter",
    }
    if query_language:
        selection["QueryLanguage"] = query_language
    if query_text:
        selection["QueryText"] = query_text[:4000]
        selection["QueryPreview"] = query_text[:500]
    return selection
