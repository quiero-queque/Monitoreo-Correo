"""Línea de comandos.

Uso:
    python -m auditor.cli usm.cl
    python -m auditor.cli usm.cl --selector google --selector selector1
    python -m auditor.cli usm.cl google.com --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .audit import audit_domain
from .dns_utils import DnsClient
from .scoring import AuditReport

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$")
ICONS = {"ok": "✅", "info": "ℹ️ ", "warning": "⚠️ ", "error": "❌"}
COLORS = {"ok": "green", "info": "cyan", "warning": "yellow", "error": "red"}


def normalize_domain(value: str) -> str:
    """Acepta 'usm.cl', 'https://usm.cl/ruta' o 'alguien@usm.cl' y devuelve 'usm.cl'."""
    d = value.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0]
    d = d.split("@")[-1].rstrip(".")
    if not DOMAIN_RE.match(d):
        raise ValueError(f"'{value}' no parece un dominio válido (ejemplo: usm.cl)")
    return d


def _shorten(text: str, limit: int = 140) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def render(report: AuditReport, console: Console) -> None:
    color = COLORS[report.verdict]
    console.print(Panel(
        Text(f"{ICONS[report.verdict]} {report.label}\n{report.summary}", style=color),
        title=report.domain, border_style=color))
    for result in report.results:
        console.print(Text(f"{ICONS[result.status]} {result.name}", style=f"bold {COLORS[result.status]}"))
        if result.record:
            console.print(Text("   " + _shorten(result.record), style="dim"))
        for f in result.findings:
            console.print(Text(f"   {ICONS[f.level]} {f.message}", style=COLORS[f.level]))
            if f.why:
                console.print(Text(f"        Por qué importa: {f.why}", style="dim"))
            if f.fix:
                console.print(Text(f"        Cómo arreglarlo: {f.fix}", style="dim"))
        console.print()


def main(argv: list[str] | None = None, dns=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(
        prog="auditor", description="Audita SPF, DKIM y DMARC de uno o varios dominios.")
    parser.add_argument("domains", nargs="+", metavar="dominio", help="ej. usm.cl")
    parser.add_argument("-s", "--selector", action="append", dest="selectors",
                        help="selector DKIM a probar (se puede repetir). Sin él se prueban selectores comunes")
    parser.add_argument("--dns", metavar="IP", help="servidor DNS a usar, ej. 8.8.8.8")
    parser.add_argument("--json", action="store_true", help="salida en JSON")
    args = parser.parse_args(argv)

    try:
        domains = [normalize_domain(d) for d in args.domains]
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    dns = dns or DnsClient(nameservers=[args.dns] if args.dns else None)
    reports = [audit_domain(d, args.selectors, dns) for d in domains]

    if args.json:
        print(json.dumps([asdict(r) for r in reports], ensure_ascii=False, indent=2))
    else:
        console = Console()
        for report in reports:
            render(report, console)
    return 1 if any(r.verdict == "error" for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
