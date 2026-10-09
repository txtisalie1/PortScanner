import socket
from collections import namedtuple

from portscanner.scanner import collect_connections

Address = namedtuple("Address", "ip port")
Connection = namedtuple("Connection", "type laddr raddr status pid")


def test_scanner_skips_listening_socket(monkeypatch) -> None:
    monkeypatch.setattr("portscanner.scanner.inspect_process", lambda *args, **kwargs: None)
    raw = Connection(socket.SOCK_STREAM, Address("0.0.0.0", 80), (), "LISTEN", 1)
    result = collect_connections(connections=[raw])
    assert result.connections == []


def test_scanner_collects_remote_connection(monkeypatch) -> None:
    from portscanner.models import ProcessInfo

    monkeypatch.setattr(
        "portscanner.scanner.inspect_process",
        lambda *args, **kwargs: ProcessInfo(pid=2, name="demo.exe"),
    )
    raw = Connection(
        socket.SOCK_STREAM,
        Address("127.0.0.1", 50000),
        Address("8.8.8.8", 443),
        "ESTABLISHED",
        2,
    )
    result = collect_connections(connections=[raw])
    assert len(result.connections) == 1
    assert result.connections[0].remote_port == 443
