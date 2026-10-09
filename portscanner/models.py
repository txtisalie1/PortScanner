"""PortScanner veri modelleri."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    pid: int | None
    name: str = "Unknown"
    executable: str | None = None
    sha256: str | None = None
    username: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ConnectionRecord:
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str | None
    remote_port: int | None
    status: str
    process: ProcessInfo

    @property
    def baseline_key(self) -> str:
        """Kararlı ve kişisel veri içermeyen karşılaştırma anahtarı."""
        process_name = self.process.name.casefold()
        return f"{self.protocol}|{process_name}|{self.remote_ip or '-'}|{self.remote_port or 0}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    rule: str
    message: str
    connection_key: str
    score: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    connections: list[ConnectionRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned_at": self.scanned_at,
            "summary": {
                "connections": len(self.connections),
                "findings": len(self.findings),
                "errors": len(self.errors),
            },
            "connections": [item.to_dict() for item in self.connections],
            "findings": [item.to_dict() for item in self.findings],
            "errors": list(self.errors),
        }
