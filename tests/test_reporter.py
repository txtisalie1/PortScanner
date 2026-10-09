import json

import pytest

from portscanner.models import ConnectionRecord, ProcessInfo, ScanResult
from portscanner.reporter import read_baseline, write_baseline, write_report


def sample_connection() -> ConnectionRecord:
    return ConnectionRecord(
        protocol="TCP",
        local_ip="127.0.0.1",
        local_port=50000,
        remote_ip="8.8.8.8",
        remote_port=443,
        status="ESTABLISHED",
        process=ProcessInfo(pid=10, name="demo.exe", sha256="abc"),
    )


def test_baseline_round_trip(tmp_path) -> None:
    target = write_baseline([sample_connection()], tmp_path / "baseline.json")
    assert read_baseline(target) == {sample_connection().baseline_key}


def test_report_contains_tool_and_summary(tmp_path) -> None:
    target = write_report(ScanResult(connections=[sample_connection()]), tmp_path / "report.json")
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["tool"] == "PortScanner"
    assert payload["summary"]["connections"] == 1


def test_invalid_baseline_is_rejected(tmp_path) -> None:
    target = tmp_path / "bad.json"
    target.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="Desteklenmeyen"):
        read_baseline(target)
