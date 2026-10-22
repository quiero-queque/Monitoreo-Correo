"""Veredicto global: combina los resultados de SPF, DKIM y DMARC."""
from __future__ import annotations

from dataclasses import dataclass

from .models import ModuleResult, worst_status

VERDICT_LABELS = {"ok": "Aprobado", "warning": "Con advertencias", "error": "Con errores"}


@dataclass
class AuditReport:
    domain: str
    results: list[ModuleResult]
    verdict: str        # "ok" | "warning" | "error"
    label: str          # "Aprobado" | "Con advertencias" | "Con errores"
    summary: str


def build_report(domain: str, results: list[ModuleResult]) -> AuditReport:
    verdict = worst_status(r.status for r in results)
    errors = sum(f.level == "error" for r in results for f in r.findings)
    warnings = sum(f.level == "warning" for r in results for f in r.findings)
    if verdict == "error":
        summary = (f"Hay {errors} error(es) que pueden causar que los correos sean rechazados "
                   "o que alguien suplante al dominio.")
    elif verdict == "warning":
        summary = f"Funciona, pero hay {warnings} advertencia(s) para mejorar."
    else:
        summary = "Todo en orden: el dominio está bien configurado."
    return AuditReport(domain, results, verdict, VERDICT_LABELS[verdict], summary)
