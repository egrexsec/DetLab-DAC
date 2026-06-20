import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

ATTACK_ID_RE = re.compile(r"^(T0000|T\d{4}(?:\.\d{3})?)$")
SELECTION_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\|(contains|endswith))?$")


class LogSource(BaseModel):
    product: str
    service: str


class Attack(BaseModel):
    technique: str
    tactic: str

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, value: str) -> str:
        if not ATTACK_ID_RE.match(value):
            raise ValueError("attack.technique must look like T1059, T1059.001, or T0000 for unmapped markdown knowledge")
        return value


class AttackContext(BaseModel):
    technique: str
    tactic: str | None = None
    name: str | None = None
    coverage: Literal["direct", "partial", "related", "gap"] = "related"
    rationale: str | None = None

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, value: str) -> str:
        if not ATTACK_ID_RE.match(value):
            raise ValueError("attack_context.technique must look like T1059, T1059.001, or T0000")
        return value


class TestRef(BaseModel):
    name: str
    source: str
    test_id: str

    @field_validator("test_id", mode="before")
    @classmethod
    def coerce_test_id(cls, value):
        return str(value)


class DetectionLogic(BaseModel):
    selection: dict[str, Any]
    condition: str

    @field_validator("selection")
    @classmethod
    def validate_selection(cls, value: dict[str, Any]) -> dict[str, Any]:
        for key, raw_value in value.items():
            if not SELECTION_KEY_RE.match(key):
                raise ValueError(
                    "detection.selection keys must use alphanumeric field names and optional |contains or |endswith operators"
                )
            if isinstance(raw_value, list):
                if not raw_value:
                    raise ValueError("detection.selection list values must not be empty")
                if any(isinstance(item, (dict, list, tuple, set)) for item in raw_value):
                    raise ValueError("detection.selection values must be scalars or flat lists of scalars")
            elif isinstance(raw_value, (dict, list, tuple, set)):
                raise ValueError("detection.selection values must be scalars or flat lists of scalars")
        return value

    @field_validator("condition")
    @classmethod
    def validate_condition(cls, value: str) -> str:
        if value.strip() != "selection":
            raise ValueError("detection.condition currently only supports 'selection'")
        return "selection"


class DataSource(BaseModel):
    name: str
    kind: Literal[
        "endpoint",
        "identity",
        "cloud",
        "network",
        "email",
        "registry",
        "process",
        "file",
        "memory",
        "script",
        "other",
    ] = "other"
    provider: str | None = None
    event_names: list[str] = Field(default_factory=list)
    notes: str | None = None


class InvestigationStep(BaseModel):
    step: str
    priority: Literal["low", "medium", "high"] = "medium"
    rationale: str | None = None


class HuntSuggestion(BaseModel):
    name: str
    hypothesis: str | None = None
    query_hint: str | None = None


class ArtifactReference(BaseModel):
    name: str
    category: Literal[
        "file",
        "registry",
        "event_log",
        "memory",
        "process",
        "network",
        "cloud_log",
        "identity_log",
        "task",
        "other",
    ] = "other"
    path: str | None = None
    notes: str | None = None


class CloudTelemetryReference(BaseModel):
    provider: Literal["aws", "azure", "gcp", "okta", "entra", "other"] = "other"
    source: str
    event_names: list[str] = Field(default_factory=list)
    notes: str | None = None


class RelatedDetection(BaseModel):
    detection_id: str
    relationship: Literal[
        "parent",
        "child",
        "correlated",
        "follow_on",
        "prerequisite",
        "similar",
        "investigate_next",
    ] = "correlated"
    rationale: str | None = None


class ResponseAction(BaseModel):
    title: str
    priority: Literal["low", "medium", "high"] = "medium"
    description: str | None = None


class Detection(BaseModel):
    id: str = Field(pattern=r"^DET-\d{4}$")
    title: str
    name: str | None = None
    description: str
    logsource: LogSource
    attack: Attack
    severity: str
    status: str
    author: str
    domain: list[Literal["endpoint", "identity", "cloud", "network", "email"]] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    tests: list[TestRef]
    detection: DetectionLogic
    attack_context: list[AttackContext] = Field(default_factory=list)
    data_sources: list[DataSource] = Field(default_factory=list)
    triage_steps: list[InvestigationStep] = Field(default_factory=list)
    investigation_steps: list[InvestigationStep] = Field(default_factory=list)
    escalation_guidance: list[str] = Field(default_factory=list)
    hunt_suggestions: list[HuntSuggestion] = Field(default_factory=list)
    artifacts: list[ArtifactReference] = Field(default_factory=list)
    velociraptor_artifacts: list[str] = Field(default_factory=list)
    cloud_telemetry: list[CloudTelemetryReference] = Field(default_factory=list)
    related_detections: list[RelatedDetection] = Field(default_factory=list)
    response_actions: list[ResponseAction] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def normalize_name_title(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "title" not in data and data.get("name"):
                data["title"] = data["name"]
            if "name" not in data and data.get("title"):
                data["name"] = data["title"]
        return data

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if value not in allowed:
            raise ValueError(f"severity must be one of: {', '.join(sorted(allowed))}")
        return value

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        allowed = {"draft", "experimental", "testing", "validated", "stable", "production", "deprecated"}
        if value not in allowed:
            raise ValueError(f"status must be one of: {', '.join(sorted(allowed))}")
        return value

    @model_validator(mode="after")
    def validate_tests_present(self) -> "Detection":
        if not self.tests:
            raise ValueError("at least one test must be defined")
        return self
