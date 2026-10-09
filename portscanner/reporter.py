"""JSON raporu ve baseline dosyalarını yönetir."""

from __future__ import annotations

import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from portscanner.models import ConnectionRecord, ScanResult


def write_report(result: ScanResult, destination: str | Path) -> Path:
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": "PortScanner",
        "version": "0.1.0",
        "host": {"name": platform.node(), "system": platform.platform()},
        **result.to_dict(),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def write_baseline(connections: list[ConnectionRecord], destination: str | Path) -> Path:
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = sorted({connection.baseline_key for connection in connections})
    payload = {
        "tool": "PortScanner",
        "format": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "entries": entries,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def read_baseline(source: str | Path) -> set[str]:
    path = Path(source).expanduser().resolve()
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Baseline dosyası bulunamadı: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Baseline geçerli JSON değil: {exc}") from exc

    if not isinstance(payload, dict) or payload.get("format") != 1:
        raise ValueError("Desteklenmeyen baseline biçimi")
    entries = payload.get("entries")
    if not isinstance(entries, list) or not all(isinstance(item, str) for item in entries):
        raise ValueError("Baseline entries alanı geçersiz")
    return set(entries)
