"""İşletim sistemindeki mevcut ağ bağlantılarını toplar."""

from __future__ import annotations

import socket
from collections.abc import Iterable

import psutil

from portscanner.models import ConnectionRecord, ScanResult
from portscanner.process_info import inspect_process


def _address_parts(address: object) -> tuple[str | None, int | None]:
    if not address:
        return None, None
    ip = getattr(address, "ip", None)
    port = getattr(address, "port", None)
    if ip is not None:
        return str(ip), int(port)
    if isinstance(address, (tuple, list)) and len(address) >= 2:
        return str(address[0]), int(address[1])
    return str(address), None


def _protocol_name(connection: object) -> str:
    conn_type = getattr(connection, "type", None)
    if conn_type == socket.SOCK_DGRAM:
        return "UDP"
    return "TCP"


def _matches_protocol(connection: object, protocol: str) -> bool:
    actual = _protocol_name(connection).casefold()
    return protocol == "all" or actual == protocol


def collect_connections(
    protocol: str = "tcp",
    *,
    include_listening: bool = False,
    include_hash: bool = True,
    connections: Iterable[object] | None = None,
) -> ScanResult:
    """Aktif bağlantıları döndürür; tekil erişim hataları taramayı durdurmaz."""
    protocol = protocol.casefold()
    if protocol not in {"tcp", "udp", "all"}:
        raise ValueError("protocol; tcp, udp veya all olmalıdır")

    result = ScanResult()
    try:
        raw_connections = connections
        if raw_connections is None:
            kind = "inet" if protocol == "all" else protocol
            raw_connections = psutil.net_connections(kind=kind)
    except (psutil.AccessDenied, PermissionError) as exc:
        result.errors.append(
            f"Bağlantılar okunamadı: {exc}. Terminali yönetici olarak çalıştırmayı deneyin."
        )
        return result
    except OSError as exc:
        result.errors.append(f"Bağlantılar okunamadı: {exc}")
        return result

    for connection in raw_connections:
        if not _matches_protocol(connection, protocol):
            continue
        remote_ip, remote_port = _address_parts(getattr(connection, "raddr", None))
        if remote_ip is None and not include_listening:
            continue
        local_ip, local_port = _address_parts(getattr(connection, "laddr", None))
        pid = getattr(connection, "pid", None)
        process = inspect_process(pid, include_hash=include_hash)
        result.connections.append(
            ConnectionRecord(
                protocol=_protocol_name(connection),
                local_ip=local_ip or "*",
                local_port=local_port or 0,
                remote_ip=remote_ip,
                remote_port=remote_port,
                status=str(getattr(connection, "status", "NONE") or "NONE"),
                process=process,
            )
        )

    result.connections.sort(
        key=lambda item: (
            item.process.name.casefold(),
            item.remote_ip or "",
            item.remote_port or 0,
        )
    )
    return result
