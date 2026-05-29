from types import SimpleNamespace

from detlab.sequences import build_eql_sequence, summarize_sequence


TEST_DETECTION = SimpleNamespace(
    title="PowerShell Followed by Network Connection",
    sequence={
        "within": "5m",
        "events": [
            {
                "name": "PowerShell Execution",
                "selection": {
                    "Image": "powershell.exe"
                },
            },
            {
                "name": "Network Connection",
                "selection": {
                    "DestinationPort": 4444
                },
            },
        ],
    },
)



def test_sequence_summary():
    summary = summarize_sequence(TEST_DETECTION)

    assert summary["sequence"] is True
    assert summary["events"] == 2
    assert summary["within"] == "5m"



def test_build_eql_sequence():
    eql = build_eql_sequence(TEST_DETECTION)

    assert "sequence with maxspan=5m" in eql
    assert "powershell.exe" in eql
    assert "4444" in eql
