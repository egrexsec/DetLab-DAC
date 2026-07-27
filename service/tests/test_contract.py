from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from detlab.contract import (
    build_generated_artifact,
    generated_artifact_is_stale,
    normalize_detlab_detection,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DETECTION_PATH = REPO_ROOT / "detections" / "windows" / "suspicious_encoded_powershell.yaml"
SCHEMA_PATH = REPO_ROOT / "schemas" / "detlab-detection-content-v1.schema.json"


class DetectionContentContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source_bytes = DETECTION_PATH.read_bytes()
        self.detection = yaml.safe_load(self.source_bytes)

    def test_rich_detection_normalizes_to_shared_v1_contract(self) -> None:
        normalized = normalize_detlab_detection(
            self.detection,
            DETECTION_PATH.relative_to(REPO_ROOT),
            self.source_bytes,
        )
        schema = yaml.safe_load(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(normalized)

        self.assertEqual(normalized["spec_version"], "1.0.0")
        self.assertEqual(normalized["source"]["format"], "detlab-canonical")
        self.assertEqual(normalized["source"]["sha256"], hashlib.sha256(self.source_bytes).hexdigest())
        self.assertEqual(normalized["logic"]["condition"], "selection")
        self.assertIn("T1059.001", normalized["attack"]["techniques"])

    def test_all_authored_detections_normalize_to_shared_v1_contract(self) -> None:
        schema = yaml.safe_load(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        paths = sorted((REPO_ROOT / "detections").rglob("*.yaml")) + sorted((REPO_ROOT / "detections").rglob("*.yml"))
        self.assertGreater(len(paths), 0)
        for path in paths:
            with self.subTest(path=path.relative_to(REPO_ROOT)):
                source_bytes = path.read_bytes()
                normalized = normalize_detlab_detection(
                    yaml.safe_load(source_bytes),
                    path.relative_to(REPO_ROOT),
                    source_bytes,
                )
                validator.validate(normalized)

    def test_generated_artifact_staleness_uses_source_hash(self) -> None:
        normalized = normalize_detlab_detection(
            self.detection,
            DETECTION_PATH.relative_to(REPO_ROOT),
            self.source_bytes,
        )
        artifact = build_generated_artifact(
            normalized,
            target="splunk",
            language="spl",
            content="index=win powershell",
            converter={"name": "pysigma-backend-splunk", "version": "2.1.0"},
        )
        self.assertFalse(generated_artifact_is_stale(normalized, artifact))
        artifact["provenance"]["source_sha256"] = "0" * 64
        self.assertTrue(generated_artifact_is_stale(normalized, artifact))


if __name__ == "__main__":
    unittest.main()
