"""Bağlantı sahibi süreçleri güvenli biçimde inceler."""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

import psutil

from portscanner.models import ProcessInfo


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as executable:
        for chunk in iter(lambda: executable.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


@lru_cache(maxsize=1024)
def inspect_process(pid: int | None, include_hash: bool = True) -> ProcessInfo:
    if pid is None:
        return ProcessInfo(pid=None, error="PID bilgisi kullanılamıyor")

    try:
        process = psutil.Process(pid)
        with process.oneshot():
            name = process.name() or "Unknown"
            executable = process.exe() or None
            try:
                username = process.username() or None
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                username = None

        file_hash = None
        hash_error = None
        if include_hash and executable:
            try:
                file_hash = sha256_file(executable)
            except (OSError, PermissionError) as exc:
                hash_error = f"SHA-256 okunamadı: {exc}"

        return ProcessInfo(
            pid=pid,
            name=name,
            executable=executable,
            sha256=file_hash,
            username=username,
            error=hash_error,
        )
    except psutil.NoSuchProcess:
        return ProcessInfo(pid=pid, error="Süreç tarama sırasında sonlandı")
    except psutil.AccessDenied:
        return ProcessInfo(pid=pid, error="Süreç bilgisine erişim reddedildi")
    except (OSError, ValueError) as exc:
        return ProcessInfo(pid=pid, error=f"Süreç okunamadı: {exc}")
