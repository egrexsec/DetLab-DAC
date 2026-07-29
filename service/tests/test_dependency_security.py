from __future__ import annotations

import subprocess
import sys


def test_service_operates_with_diskcache_imports_blocked() -> None:
    script = """
import sys
sys.modules['diskcache'] = None
sys.modules['diskcache.core'] = None
from detlab.api import app
from detlab.converter import ConverterService
assert app.title == 'DetLab Sigma Conversion API'
service = ConverterService()
assert service.backends()
result = service.convert('''
title: DiskCache-free conversion
logsource:
  product: windows
detection:
  selection:
    EventID: 1
  condition: selection
''', 'splunk')
assert result['outputs']
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
