from __future__ import annotations

import re
import unittest
from pathlib import Path


class CiSecurityPolicyTests(unittest.TestCase):
    def test_contract_job_runs_dependency_policy_script(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")

        self.assertRegex(
            workflow,
            re.compile(
                r"- name: Audit Python dependencies\s+"
                r"run: (?:sh )?service/audit-dependencies\.sh"
            ),
        )


if __name__ == "__main__":
    unittest.main()
