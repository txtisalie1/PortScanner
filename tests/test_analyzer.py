from portscanner.analyzer import analyze_connections
from portscanner.models import ConnectionRecord, ProcessInfo


def connection(
    *, process: str = "browser.exe", remote_ip: str = "8.8.8.8", remote_port: int = 443
) -> ConnectionRecord:
    return ConnectionRecord(
        protocol="TCP",
        local_ip="192.168.1.10",
        local_port=50000,
        remote_ip=remote_ip,
        remote_port=remote_port,
        status="ESTABLISHED",
        process=ProcessInfo(pid=123, name=process),
    )


def test_common_https_connection_has_no_finding() -> None:
    assert analyze_connections([connection()]) == []


def test_unknown_process_is_flagged() -> None:
    findings = analyze_connections([connection(process="Unknown")])
    assert any(item.rule == "unknown-process" for item in findings)


def test_public_sensitive_service_is_high_risk() -> None:
    findings = analyze_connections([connection(remote_port=445)])
    assert any(
        item.rule == "public-sensitive-service" and item.severity == "high" for item in findings
    )


def test_private_sensitive_service_is_not_flagged_as_public() -> None:
    findings = analyze_connections([connection(remote_ip="192.168.1.1", remote_port=445)])
    assert not any(item.rule == "public-sensitive-service" for item in findings)


def test_new_baseline_entry_is_reported() -> None:
    findings = analyze_connections([connection()], baseline_keys=set())
    assert any(item.rule == "new-baseline-entry" for item in findings)
