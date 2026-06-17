import re
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
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
            raise ValueError("attack.technique must look like T1059 or T1059.001")
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


class Detection(BaseModel):
    id: str = Field(pattern=r"^DET-\d{4}$")
    title: str
    description: str
    logsource: LogSource
    attack: Attack
    severity: str
    status: str
    author: str
    references: list[str] = []
    falsepositives: list[str] = []
    tests: list[TestRef]
    detection: DetectionLogic

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
        allowed = {"experimental", "testing", "stable", "deprecated"}
        if value not in allowed:
            raise ValueError(f"status must be one of: {', '.join(sorted(allowed))}")
        return value

    @model_validator(mode="after")
    def validate_tests_present(self) -> "Detection":
        if not self.tests:
            raise ValueError("at least one test must be defined")
        return self
