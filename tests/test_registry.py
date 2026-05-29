from pathlib import Path

from detlab.registry import calculate_checksum



def test_calculate_checksum(tmp_path: Path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("detlab", encoding="utf-8")

    checksum = calculate_checksum(test_file)

    assert isinstance(checksum, str)
    assert len(checksum) == 64
