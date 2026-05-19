"""
recon-engine CLI

Entry point for all user-facing commands. The CLI layer is intentionally thin:
it validates flags, delegates to the engine, and renders results using Rich.
No business logic lives here.

Usage:
    python main.py scan example.com
    python main.py ports example.com --ports 22,80,443
    python main.py subdomains example.com
    python main.py export example.com
    python main.py report example.com
    python main.py sessions
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.engine import ReconEngine
from core.validator import parse_target
from database.store import ScanStore
from reports.markdown_report import generate_markdown_report
from utils.exporter import export_session_json
from utils.logging_config import configure_logging

app = typer.Typer(
    name="recon-engine",
    help="Professional reconnaissance toolkit for authorized security assessments.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
error_console = Console(stderr=True, style="bold red")

_BANNER = """
[bold cyan]recon-engine[/bold cyan] [dim]v1.0.0[/dim]
[dim]Authorized security reconnaissance toolkit[/dim]
"""

_DISCLAIMER = (
    "[yellow]This tool is for authorized security testing only. "
    "Scanning targets without explicit permission is illegal.[/yellow]"
)


def _get_store() -> ScanStore:
    return ScanStore(db_path=Path("outputs/recon.db"))


def _confirm_authorized(target: str) -> None:
    """Prompt the operator to confirm authorization before scanning."""
    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n\n{_DISCLAIMER}",
            title="[bold red]Authorization Required[/bold red]",
            border_style="red",
        )
    )
    confirmed = typer.confirm("Do you have explicit authorization to scan this target?")
    if not confirmed:
        console.print("[red]Scan aborted.[/red]")
        raise typer.Exit(1)


def _parse_port_list(ports_str: Optional[str]) -> Optional[List[int]]:
    """Parse a comma-separated port string into a list of integers."""
    if ports_str is None:
        return None
    try:
        result = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
        if not result:
            raise ValueError("Empty port list")
        return result
    except ValueError as exc:
        error_console.print(f"Invalid port specification: {exc}")
        raise typer.Exit(1)


# ------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain, IP, or URL to scan"),
    ports: Optional[str] = typer.Option(
        None, "--ports", "-p", help="Comma-separated port list (default: common ports)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    no_confirm: bool = typer.Option(
        False, "--no-confirm", help="Skip authorization prompt (use in CI)"
    ),
) -> None:
    """Run a full scan: subdomains + ports + HTTP fingerprinting."""
    configure_logging(level=logging.DEBUG if verbose else logging.WARNING)
    console.print(_BANNER)

    try:
        parsed = parse_target(target)
    except ValueError as exc:
        error_console.print(f"Invalid target: {exc}")
        raise typer.Exit(1)

    if not no_confirm:
        _confirm_authorized(parsed.hostname)

    port_list = _parse_port_list(ports)
    store = _get_store()
    engine = ReconEngine(store)

    with console.status(f"[bold cyan]Scanning {parsed.hostname}...[/bold cyan]"):
        session = asyncio.run(engine.run_full_scan(target, port_list=port_list))

    _render_session_summary(session)


@app.command()
def subdomains(
    target: str = typer.Argument(..., help="Domain to enumerate subdomains for"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    no_confirm: bool = typer.Option(False, "--no-confirm"),
) -> None:
    """Enumerate subdomains using passive sources (crt.sh)."""
    configure_logging(level=logging.DEBUG if verbose else logging.WARNING)
    console.print(_BANNER)

    try:
        parsed = parse_target(target)
    except ValueError as exc:
        error_console.print(f"Invalid target: {exc}")
        raise typer.Exit(1)

    if not no_confirm:
        _confirm_authorized(parsed.hostname)

    store = _get_store()
    engine = ReconEngine(store)

    with console.status("[bold cyan]Enumerating subdomains...[/bold cyan]"):
        session = asyncio.run(engine.run_subdomain_scan(target))

    _render_subdomains(session)


@app.command()
def ports(
    target: str = typer.Argument(..., help="Domain or IP to port-scan"),
    port_list: Optional[str] = typer.Option(
        None, "--ports", "-p", help="Comma-separated ports (default: common ports)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    no_confirm: bool = typer.Option(False, "--no-confirm"),
) -> None:
    """Perform async TCP port scanning."""
    configure_logging(level=logging.DEBUG if verbose else logging.WARNING)
    console.print(_BANNER)

    try:
        parsed = parse_target(target)
    except ValueError as exc:
        error_console.print(f"Invalid target: {exc}")
        raise typer.Exit(1)

    if not no_confirm:
        _confirm_authorized(parsed.hostname)

    parsed_ports = _parse_port_list(port_list)
    store = _get_store()
    engine = ReconEngine(store)

    with console.status("[bold cyan]Scanning ports...[/bold cyan]"):
        session = asyncio.run(engine.run_port_scan(target, port_list=parsed_ports))

    _render_ports(session)


@app.command()
def export(
    target: str = typer.Argument(..., help="Target to export results for"),
) -> None:
    """Export the most recent scan results for a target to JSON."""
    store = _get_store()
    row = store.get_session_by_target(target)

    if not row:
        error_console.print(f"No scan results found for '{target}'.")
        raise typer.Exit(1)

    session = store.load_full_session(row["id"])
    if not session:
        error_console.print("Session data could not be loaded.")
        raise typer.Exit(1)

    path = export_session_json(session)
    console.print(f"[green]JSON export written:[/green] {path}")


@app.command()
def report(
    target: str = typer.Argument(..., help="Target to generate a report for"),
) -> None:
    """Generate a Markdown report from the most recent scan results."""
    store = _get_store()
    row = store.get_session_by_target(target)

    if not row:
        error_console.print(f"No scan results found for '{target}'.")
        raise typer.Exit(1)

    session = store.load_full_session(row["id"])
    if not session:
        error_console.print("Session data could not be loaded.")
        raise typer.Exit(1)

    path = generate_markdown_report(session)
    console.print(f"[green]Markdown report written:[/green] {path}")


@app.command()
def sessions() -> None:
    """List all scan sessions in the database."""
    store = _get_store()
    rows = store.list_sessions()

    if not rows:
        console.print("[yellow]No scan sessions found.[/yellow]")
        return

    table = Table(title="Scan Sessions", box=box.ROUNDED)
    table.add_column("ID", style="dim", width=6)
    table.add_column("Target", style="cyan")
    table.add_column("Started", style="green")
    table.add_column("Finished")
    table.add_column("Notes")

    for row in rows:
        table.add_row(
            str(row["id"]),
            row["target"],
            row["started_at"][:19],
            row["finished_at"][:19] if row["finished_at"] else "[dim]running[/dim]",
            row["notes"] or "",
        )

    console.print(table)


# ------------------------------------------------------------------
# Rich rendering helpers
# ------------------------------------------------------------------


def _render_session_summary(session) -> None:
    _render_subdomains(session)
    _render_ports(session)
    _render_http(session)


def _render_subdomains(session) -> None:
    if not session.subdomains:
        console.print("\n[yellow]No subdomains discovered.[/yellow]")
        return

    table = Table(
        title=f"Subdomains ({len(session.subdomains)})",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("Subdomain", style="cyan")
    table.add_column("Source", style="dim")
    table.add_column("Resolved", justify="center")
    table.add_column("IP Address")

    for r in session.subdomains:
        resolved_icon = "[green]✓[/green]" if r.resolved else "[dim]-[/dim]"
        table.add_row(r.subdomain, r.source, resolved_icon, r.ip_address or "")

    console.print(table)


def _render_ports(session) -> None:
    open_ports = [p for p in session.ports if p.state == "open"]
    if not open_ports:
        console.print("\n[yellow]No open ports found.[/yellow]")
        return

    table = Table(
        title=f"Open Ports ({len(open_ports)})",
        box=box.ROUNDED,
    )
    table.add_column("Port", style="bold")
    table.add_column("Protocol")
    table.add_column("Service", style="cyan")
    table.add_column("Banner", style="dim")

    for p in open_ports:
        banner = (p.banner[:60] + "…") if p.banner and len(p.banner) > 60 else (p.banner or "")
        table.add_row(str(p.port), p.protocol.upper(), p.service or "-", banner)

    console.print(table)


def _render_http(session) -> None:
    if not session.http_fingerprints:
        console.print("\n[yellow]No HTTP endpoints reached.[/yellow]")
        return

    table = Table(title="HTTP Fingerprints", box=box.ROUNDED)
    table.add_column("URL", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Server")
    table.add_column("Technologies")
    table.add_column("Time (ms)", justify="right")

    for fp in session.http_fingerprints:
        status_style = (
            "green" if fp.status_code and fp.status_code < 300
            else "yellow" if fp.status_code and fp.status_code < 500
            else "red"
        )
        table.add_row(
            fp.url,
            f"[{status_style}]{fp.status_code or 'N/A'}[/{status_style}]",
            fp.server or "-",
            ", ".join(fp.technologies) or "-",
            str(fp.response_time_ms or "-"),
        )

    console.print(table)


if __name__ == "__main__":
    app()
