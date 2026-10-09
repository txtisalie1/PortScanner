"""Açıklanabilir, muhafazakâr bağlantı risk kuralları."""

from __future__ import annotations

import ipaddress
from collections.abc import Collection, Iterable

from portscanner.models import ConnectionRecord, Finding

COMMON_REMOTE_PORTS = {
    20,
    21,
    22,
    25,
    53,
    67,
    68,
    80,
    110,
    123,
    143,
    161,
    389,
    443,
    465,
    587,
    636,
    853,
    993,
    995,
    1433,
    3306,
    5060,
    5222,
    5432,
    8000,
    8080,
    8443,
}
EXPOSED_SERVICE_PORTS = {23, 135, 137, 138, 139, 445, 3389, 5900}


def _is_public(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip.split("%", 1)[0]).is_global
    except ValueError:
        return False


def analyze_connections(
    connections: Iterable[ConnectionRecord],
    *,
    baseline_keys: Collection[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for connection in connections:
        key = connection.baseline_key
        remote_port = connection.remote_port

        if connection.process.name == "Unknown":
            findings.append(
                Finding(
                    severity="medium",
                    rule="unknown-process",
                    message="Bağlantının sahibi olan süreç tanımlanamadı.",
                    connection_key=key,
                    score=35,
                )
            )

        if remote_port in EXPOSED_SERVICE_PORTS and _is_public(connection.remote_ip):
            findings.append(
                Finding(
                    severity="high",
                    rule="public-sensitive-service",
                    message=f"Genel internette hassas servis portuna ({remote_port}) bağlantı görüldü.",
                    connection_key=key,
                    score=70,
                )
            )
        elif (
            remote_port
            and remote_port not in COMMON_REMOTE_PORTS
            and _is_public(connection.remote_ip)
        ):
            findings.append(
                Finding(
                    severity="low",
                    rule="uncommon-remote-port",
                    message=f"Yaygın olmayan uzak port kullanılıyor: {remote_port}.",
                    connection_key=key,
                    score=20,
                )
            )

        if baseline_keys is not None and key not in baseline_keys:
            findings.append(
                Finding(
                    severity="info",
                    rule="new-baseline-entry",
                    message="Bu süreç, adres ve port birleşimi baseline içinde yok.",
                    connection_key=key,
                    score=10,
                )
            )

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(findings, key=lambda item: (severity_order[item.severity], -item.score))
