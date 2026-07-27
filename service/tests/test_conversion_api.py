from __future__ import annotations

import time
import unittest

from fastapi.testclient import TestClient

from detlab.api import create_app
from detlab.converter import ConverterService


VALID_SIGMA = """title: Suspicious Encoded PowerShell
id: 11111111-1111-4111-8111-111111111111
status: experimental
description: Detect encoded PowerShell command lines.
author: mell0wx
date: 2026-07-27
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
falsepositives:
  - Administrative automation
level: high
tags:
  - attack.execution
  - attack.t1059.001
"""


class SlowConverter:
    def backends(self):
        return [{"id": "splunk", "language": "spl", "package": "test", "version": "1"}]

    def convert(self, source: str, target: str):
        time.sleep(0.05)
        return {}


class ConversionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(create_app(conversion_timeout_seconds=2.0))

    def test_backend_registry_is_explicit_and_versioned(self) -> None:
        response = self.client.get("/v1/backends")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        ids = {item["id"] for item in payload["backends"]}
        self.assertEqual(ids, {"splunk", "elastic-eql", "elastic-esql", "microsoft-kusto"})
        for backend in payload["backends"]:
            self.assertTrue(backend["package"])
            self.assertTrue(backend["version"])

    def test_convert_returns_query_and_reproducible_provenance(self) -> None:
        response = self.client.post("/v1/convert", json={"source": VALID_SIGMA, "target": "splunk"})
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["target"], "splunk")
        self.assertEqual(payload["language"], "spl")
        self.assertTrue(payload["outputs"])
        self.assertRegex(payload["source_sha256"], r"^[a-f0-9]{64}$")
        self.assertEqual(payload["provenance"]["spec_version"], "1.0.0")
        self.assertEqual(payload["provenance"]["source_sha256"], payload["source_sha256"])

    def test_unsupported_backend_is_rejected_without_dynamic_loading(self) -> None:
        response = self.client.post("/v1/convert", json={"source": VALID_SIGMA, "target": "python:os.system"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["detail"]["code"], "unsupported_backend")

    def test_malformed_and_unsafe_yaml_are_rejected(self) -> None:
        for source in ("title: [", "!!python/object/apply:os.system ['id']"):
            with self.subTest(source=source):
                response = self.client.post("/v1/convert", json={"source": source, "target": "splunk"})
                self.assertEqual(response.status_code, 422)
                self.assertEqual(response.json()["detail"]["code"], "invalid_sigma")

    def test_source_size_limit_is_enforced(self) -> None:
        response = self.client.post("/v1/convert", json={"source": "A" * 262145, "target": "splunk"})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["detail"]["code"], "source_too_large")

    def test_conversion_timeout_is_bounded(self) -> None:
        client = TestClient(create_app(converter=SlowConverter(), conversion_timeout_seconds=0.01))
        response = client.post("/v1/convert", json={"source": VALID_SIGMA, "target": "splunk"})
        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.json()["detail"]["code"], "conversion_timeout")


class ConverterServiceTests(unittest.TestCase):
    def test_all_registered_backends_convert_the_same_sigma_source(self) -> None:
        service = ConverterService()
        for backend in service.backends():
            with self.subTest(target=backend["id"]):
                result = service.convert(VALID_SIGMA, backend["id"])
                self.assertTrue(result["outputs"])
                self.assertEqual(result["target"], backend["id"])


if __name__ == "__main__":
    unittest.main()
