"""PortScanner komut satırı arayüzü."""

from __future__ import annotations

import argparse
import os
import sys
import time

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from portscanner import __version__
from portscanner.analyzer import analyze_connections
from portscanner.models import ScanResult
from portscanner.reporter import read_baseline, write_baseline, write_report
from portscanner.scanner import collect_connections

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscanner",
        description=(
            "Windows ağ bağlantılarını süreç bilgileriyle eşleştirir ve açıklanabilir "
            "güvenlik uyarıları üretir."
        ),
    )
    parser.add_argument("--version", action="version", version=f"PortScanner {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Mevcut bağlantıları bir kez tara")
    _add_scan_options(scan)
    scan.add_argument("--json", metavar="DOSYA", help="Sonucu JSON raporu olarak kaydet")
    scan.add_argument("--baseline", metavar="DOSYA", help="Sonucu baseline ile karşılaştır")

    monitor = subparsers.add_parser("monitor", help="Bağlantıları düzenli aralıklarla izle")
    _add_scan_options(monitor)
    monitor.add_argument(
        "--interval", type=float, default=3.0, help="Yenileme aralığı, saniye (varsayılan: 3)"
    )
    monitor.add_argument("--baseline", metavar="DOSYA", help="Sonucu baseline ile karşılaştır")

    baseline = subparsers.add_parser("baseline", help="Normal bağlantı baseline'ı oluştur")
    _add_scan_options(baseline)
    baseline.add_argument(
        "--output", "-o", default="portscanner-baseline.json", help="Baseline dosyası"
    )

    return parser


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--protocol", choices=("tcp", "udp", "all"), default="tcp", help="Protokol")
    parser.add_argument(
        "--listening", action="store_true", help="Uzak ucu olmayan dinleyen soketleri de göster"
    )
    parser.add_argument(
        "--no-hash", action="store_true", help="Çalıştırılabilir dosyaların SHA-256 özetini alma"
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="Gösterilecek satır sayısı (0: sınırsız)"
    )


def _load_baseline(path: str | None) -> set[str] | None:
    if not path:
        return None
    return read_baseline(path)


def _scan(args: argparse.Namespace, baseline: set[str] | None = None) -> ScanResult:
    result = collect_connections(
        args.protocol,
        include_listening=args.listening,
        include_hash=not args.no_hash,
    )
    result.findings = analyze_connections(result.connections, baseline_keys=baseline)
    return result


def _status_style(status: str) -> str:
    return {
        "ESTABLISHED": "green",
        "LISTEN": "cyan",
        "CLOSE_WAIT": "yellow",
        "TIME_WAIT": "dim",
    }.get(status, "white")


def _render_result(result: ScanResult, limit: int = 0) -> Table:
    table = Table(title=f"PortScanner v{__version__} | Ağ Bağlantıları", expand=True)
    table.add_column("Proto", style="cyan", no_wrap=True)
    table.add_column("PID", justify="right", no_wrap=True)
    table.add_column("Süreç", style="green")
    table.add_column("Yerel Adres")
    table.add_column("Uzak Adres")
    table.add_column("Durum")
    table.add_column("Risk", justify="center")

    findings_by_key: dict[str, list[str]] = {}
    for finding in result.findings:
        findings_by_key.setdefault(finding.connection_key, []).append(finding.severity)
    risk_order = {"high": 4, "medium": 3, "low": 2, "info": 1}
    risk_style = {"high": "bold red", "medium": "yellow", "low": "blue", "info": "dim"}

    rows = result.connections[:limit] if limit > 0 else result.connections
    for connection in rows:
        severities = findings_by_key.get(connection.baseline_key, [])
        risk = max(severities, key=lambda item: risk_order[item]) if severities else "-"
        local = f"{connection.local_ip}:{connection.local_port}"
        remote = f"{connection.remote_ip}:{connection.remote_port}" if connection.remote_ip else "-"
        table.add_row(
            connection.protocol,
            str(connection.process.pid or "N/A"),
            connection.process.name,
            local,
            remote,
            Text(connection.status, style=_status_style(connection.status)),
            Text(risk.upper(), style=risk_style.get(risk, "green")),
        )
    return table


def _print_summary(result: ScanResult, *, shown_limit: int = 0) -> None:
    review_count = sum(1 for item in result.findings if item.severity != "info")
    console.print(f"\n[green][+] {len(result.connections)} bağlantı analiz edildi[/green]")
    if shown_limit > 0 and len(result.connections) > shown_limit:
        console.print(f"[dim]    İlk {shown_limit} bağlantı gösterildi[/dim]")
    if review_count:
        console.print(f"[yellow][!] {review_count} bulgu inceleme gerektiriyor[/yellow]")
    else:
        console.print("[green][+] İnceleme gerektiren kural bulgusu yok[/green]")
    new_count = sum(1 for item in result.findings if item.rule == "new-baseline-entry")
    if new_count:
        console.print(f"[cyan][i] {new_count} yeni baseline kaydı görüldü[/cyan]")
    for error in result.errors:
        console.print(f"[red][x] {error}[/red]")
    console.print(
        "[dim]Uyarılar açıklanabilir sezgisel kurallardır; tek başına zararlı yazılım "
        "teşhisi değildir.[/dim]"
    )


def _run_scan(args: argparse.Namespace) -> int:
    try:
        baseline = _load_baseline(args.baseline)
    except ValueError as exc:
        console.print(f"[red]Hata: {exc}[/red]")
        return 2
    result = _scan(args, baseline)
    console.print(_render_result(result, args.limit))
    _print_summary(result, shown_limit=args.limit)
    if args.json:
        try:
            path = write_report(result, args.json)
        except OSError as exc:
            console.print(f"[red]Rapor yazılamadı: {exc}[/red]")
            return 1
        console.print(f"[green][+] JSON raporu: {path}[/green]")
    return 1 if result.errors and not result.connections else 0


def _run_baseline(args: argparse.Namespace) -> int:
    result = _scan(args)
    if result.errors and not result.connections:
        _print_summary(result)
        return 1
    try:
        path = write_baseline(result.connections, args.output)
    except OSError as exc:
        console.print(f"[red]Baseline yazılamadı: {exc}[/red]")
        return 1
    console.print(
        Panel.fit(
            f"[green]{len(result.connections)} bağlantı kaydedildi[/green]\n{path}",
            title="PortScanner Baseline",
        )
    )
    return 0


def _run_monitor(args: argparse.Namespace) -> int:
    if args.interval < 0.5:
        console.print("[red]Hata: --interval en az 0.5 olmalıdır.[/red]")
        return 2
    try:
        baseline = _load_baseline(args.baseline)
    except ValueError as exc:
        console.print(f"[red]Hata: {exc}[/red]")
        return 2
    console.print("[dim]Canlı izlemeyi durdurmak için Ctrl+C kullanın.[/dim]")
    try:
        with Live(console=console, refresh_per_second=4, screen=False) as live:
            while True:
                result = _scan(args, baseline)
                live.update(_render_result(result, args.limit), refresh=True)
                time.sleep(args.interval)
    except KeyboardInterrupt:
        console.print("\n[cyan]İzleme durduruldu.[/cyan]")
        return 0


def main(argv: list[str] | None = None) -> int:
    if os.name != "nt":
        console.print("[yellow]Not: PortScanner Windows için tasarlanmıştır.[/yellow]")
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        args = parser.parse_args(["scan", *(argv or [])])
    try:
        if args.command == "baseline":
            return _run_baseline(args)
        if args.command == "monitor":
            return _run_monitor(args)
        return _run_scan(args)
    except KeyboardInterrupt:
        console.print("\n[cyan]İşlem iptal edildi.[/cyan]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
