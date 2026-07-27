"""Pinned, explicit pySigma backend registry and conversion service."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
from dataclasses import dataclass
from typing import Any, Callable

from sigma.backends.elasticsearch import EqlBackend, ESQLBackend
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection


class ConversionError(ValueError):
    """Raised when authored Sigma cannot be parsed or converted safely."""


@dataclass(frozen=True)
class BackendDefinition:
    id: str
    language: str
    package: str
    factory: Callable[[], Any]

    def public(self) -> dict[str, str]:
        return {
            "id": self.id,
            "language": self.language,
            "package": self.package,
            "version": importlib.metadata.version(self.package),
        }


BACKENDS = (
    BackendDefinition("splunk", "spl", "pysigma-backend-splunk", SplunkBackend),
    BackendDefinition("elastic-eql", "eql", "pysigma-backend-elasticsearch", EqlBackend),
    BackendDefinition("elastic-esql", "esql", "pysigma-backend-elasticsearch", ESQLBackend),
    BackendDefinition("microsoft-kusto", "kql", "pysigma-backend-kusto", KustoBackend),
)


class ConverterService:
    def __init__(self) -> None:
        self._registry = {definition.id: definition for definition in BACKENDS}

    def backends(self) -> list[dict[str, str]]:
        return [definition.public() for definition in BACKENDS]

    def convert(self, source: str, target: str) -> dict[str, Any]:
        definition = self._registry.get(target)
        if definition is None:
            raise KeyError(target)
        try:
            collection = SigmaCollection.from_yaml(source)
        except Exception as exc:
            raise ConversionError("Sigma source is invalid") from exc
        try:
            rendered = definition.factory().convert(collection)
        except Exception as exc:
            raise ConversionError("Sigma source is unsupported by the selected backend") from exc
        outputs = [item if isinstance(item, str) else json.dumps(item, sort_keys=True) for item in rendered]
        if not outputs or not all(item.strip() for item in outputs):
            raise ConversionError("Selected backend produced no query output")
        source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
        backend = definition.public()
        return {
            "target": definition.id,
            "language": definition.language,
            "outputs": outputs,
            "source_sha256": source_sha256,
            "provenance": {
                "spec_version": "1.0.0",
                "source_sha256": source_sha256,
                "converter": {"name": backend["package"], "version": backend["version"]},
            },
        }
