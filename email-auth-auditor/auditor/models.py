"""Estructuras de datos compartidas por todos los módulos.

Cada módulo (SPF, DKIM, DMARC) devuelve un ModuleResult con:
  - status:      "ok" | "warning" | "error"
  - record:      el registro DNS analizado (o None)
  - findings:    lista de Finding (qué se encontró, por qué importa, cómo arreglarlo)
  - explanation: resumen corto en lenguaje simple
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class Finding:
    level: str          # "ok" | "info" | "warning" | "error"
    message: str        # qué se encontró
    why: str = ""       # por qué importa
    fix: str = ""       # cómo arreglarlo


@dataclass
class ModuleResult:
    name: str
    status: str
    record: str | None
    findings: list[Finding] = field(default_factory=list)
    explanation: str = ""


def worst_status(levels: Iterable[str]) -> str:
    levels = list(levels)
    if "error" in levels:
        return "error"
    if "warning" in levels:
        return "warning"
    return "ok"


def build_result(name: str, record: str | None, findings: list[Finding]) -> ModuleResult:
    """Calcula el estado general de un módulo y su explicación corta."""
    status = worst_status(f.level for f in findings)
    errors = [f for f in findings if f.level == "error"]
    warnings = [f for f in findings if f.level == "warning"]
    if errors:
        explanation = f"{len(errors)} error(es) a corregir. Principal: {errors[0].message}"
    elif warnings:
        explanation = f"Funciona, pero hay {len(warnings)} mejora(s) recomendada(s). Principal: {warnings[0].message}"
    else:
        explanation = "Configuración correcta."
    return ModuleResult(name=name, status=status, record=record, findings=findings, explanation=explanation)
