"""Módulo SPF (RFC 7208).

Valida: existencia, un solo registro, sintaxis, política final (-all / ~all / +all),
mecanismos obsoletos (ptr) y el límite de 10 consultas DNS (siguiendo los include).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable

from .dns_utils import DNSLookupError
from .models import Finding, ModuleResult, build_result

TxtLookup = Callable[[str], "list[str]"]

MAX_LOOKUPS = 10
WARN_LOOKUPS = 8
MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}  # cada uno cuenta como 1 consulta

_MODIFIER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.\-]*)=(.*)$")
_MECHANISM_RE = re.compile(r"^([+\-~?])?([A-Za-z0-9]+)(.*)$")


@dataclass
class Term:
    qualifier: str          # + - ~ ?
    mechanism: str
    value: str | None
    raw: str


def find_spf_records(txt_records: list[str]) -> list[str]:
    """Los TXT que empiezan con v=spf1."""
    return [r for r in txt_records if r.strip().lower().split()[:1] == ["v=spf1"]]


def parse_record(record: str) -> tuple[list[Term], dict[str, str], list[str]]:
    """Devuelve (mecanismos, modificadores, errores_de_sintaxis)."""
    terms: list[Term] = []
    modifiers: dict[str, str] = {}
    errors: list[str] = []
    for raw in record.strip().split()[1:]:
        mod = _MODIFIER_RE.match(raw)
        if mod:
            modifiers.setdefault(mod.group(1).lower(), mod.group(2))
            continue
        m = _MECHANISM_RE.match(raw)
        if not m:
            errors.append(f"Término no válido: '{raw}'")
            continue
        qualifier, name, rest = m.group(1) or "+", m.group(2).lower(), m.group(3)
        if name not in MECHANISMS:
            errors.append(f"Mecanismo desconocido: '{raw}'")
            continue
        value = None
        if rest.startswith(":"):
            value = rest[1:]
        elif rest and not rest.startswith("/"):
            errors.append(f"Término no válido: '{raw}'")
            continue
        terms.append(Term(qualifier, name, value, raw))
    return terms, modifiers, errors


def _validate_term(term: Term) -> str | None:
    if term.mechanism in ("ip4", "ip6"):
        if not term.value:
            return f"'{term.raw}': falta la dirección IP"
        try:
            net = ipaddress.ip_network(term.value, strict=False)
        except ValueError:
            return f"'{term.raw}': dirección o rango IP inválido"
        if (term.mechanism == "ip4") != (net.version == 4):
            return f"'{term.raw}': la versión de IP no coincide con el mecanismo"
    elif term.mechanism in ("include", "exists") and not term.value:
        return f"'{term.raw}': falta el dominio"
    elif term.mechanism == "all" and term.value is not None:
        return f"'{term.raw}': 'all' no admite valor"
    return None


class _LookupWalker:
    """Cuenta las consultas DNS que exige un SPF, siguiendo include y redirect."""

    def __init__(self, txt: TxtLookup):
        self.txt = txt
        self.count = 0
        self.problems: list[str] = []

    def walk(self, record: str, path: frozenset[str]) -> None:
        terms, modifiers, _ = parse_record(record)
        for term in terms:
            if term.mechanism in LOOKUP_MECHANISMS:
                self.count += 1
            if term.mechanism == "include" and term.value:
                self._follow(term.value, path)
        if "redirect" in modifiers:
            self.count += 1
            self._follow(modifiers["redirect"], path)

    def _follow(self, target: str, path: frozenset[str]) -> None:
        if self.count > MAX_LOOKUPS:
            return  # ya es un error; no seguimos consultando
        target = target.strip().rstrip(".").lower()
        if "%" in target:
            return  # macros: no se pueden resolver sin un correo real
        if target in path:
            self.problems.append(f"Bucle de include/redirect en {target}")
            return
        try:
            records = find_spf_records(self.txt(target))
        except DNSLookupError as exc:
            self.problems.append(f"No se pudo consultar {target}: {exc}")
            return
        if not records:
            self.problems.append(f"{target} no tiene registro SPF, así que el include/redirect falla")
            return
        if len(records) > 1:
            self.problems.append(f"{target} tiene más de un registro SPF")
            return
        self.walk(records[0], path | {target})


def _check_policy(terms: list[Term], modifiers: dict[str, str]) -> list[Finding]:
    all_idx = [i for i, t in enumerate(terms) if t.mechanism == "all"]
    findings: list[Finding] = []
    if all_idx:
        i = all_idx[0]
        q = terms[i].qualifier
        if i != len(terms) - 1:
            findings.append(Finding(
                "warning", "Hay mecanismos después de 'all'",
                why="SPF deja de evaluar al llegar a 'all': lo que venga después se ignora.",
                fix="Mueve 'all' al final del registro."))
        if q == "-":
            findings.append(Finding("ok", "Termina en -all: rechaza a los remitentes no autorizados"))
        elif q == "~":
            findings.append(Finding(
                "info", "Termina en ~all: marca como sospechosos a los remitentes no autorizados",
                why="~all (softfail) no los rechaza, solo los marca. Es aceptable, sobre todo junto con DMARC.",
                fix="Cuando confirmes que todos tus remitentes legítimos están en el SPF, cambia a -all."))
        else:
            sym = "+all" if q == "+" else "?all"
            findings.append(Finding(
                "error", f"Termina en {sym}: permite que cualquier servidor envíe correo como este dominio",
                why="Anula la protección de SPF: cualquiera podría suplantar al dominio.",
                fix="Cambia el final a -all (o ~all mientras pruebas) y deja solo tus servidores autorizados."))
    elif "redirect" in modifiers:
        findings.append(Finding(
            "info", f"Usa redirect={modifiers['redirect']}: la política final la define ese dominio"))
    else:
        findings.append(Finding(
            "warning", "El registro no termina con 'all' ni con 'redirect'",
            why="Sin una política final, los remitentes no listados quedan sin ser evaluados (resultado neutral).",
            fix="Agrega -all (o ~all) al final del registro."))
    return findings


def _check_deprecated(terms: list[Term]) -> list[Finding]:
    if any(t.mechanism == "ptr" for t in terms):
        return [Finding(
            "warning", "Usa el mecanismo 'ptr'",
            why="El RFC 7208 lo desaconseja: es lento, poco fiable y gasta consultas DNS.",
            fix="Reemplázalo por ip4:, ip6: o include:.")]
    return []


def _check_lookups(domain: str, record: str, txt: TxtLookup) -> list[Finding]:
    walker = _LookupWalker(txt)
    walker.walk(record, frozenset({domain.lower()}))
    findings: list[Finding] = []
    if walker.count > MAX_LOOKUPS:
        findings.append(Finding(
            "error", f"Supera el límite de {MAX_LOOKUPS} consultas DNS (más de {MAX_LOOKUPS})",
            why="Con más de 10 consultas el SPF da error permanente y los receptores lo ignoran o rechazan el correo.",
            fix="Quita includes que no uses o reemplázalos por rangos ip4:/ip6: fijos."))
    elif walker.count >= WARN_LOOKUPS:
        findings.append(Finding(
            "warning", f"Usa {walker.count} de {MAX_LOOKUPS} consultas DNS permitidas",
            why="Está cerca del límite: agregar un proveedor más podría romper el SPF.",
            fix="Simplifica el registro antes de agregar nuevos includes."))
    else:
        findings.append(Finding("ok", f"Usa {walker.count} de {MAX_LOOKUPS} consultas DNS permitidas"))
    for problem in walker.problems:
        findings.append(Finding(
            "error", problem,
            why="Un include/redirect roto hace que todo el SPF falle.",
            fix="Corrige o elimina ese include/redirect."))
    return findings


def analyze_spf(domain: str, txt_records: list[str], txt: TxtLookup) -> ModuleResult:
    """Analiza los TXT del dominio. `txt` se usa para seguir los include."""
    records = find_spf_records(txt_records)
    if not records:
        return build_result("SPF", None, [Finding(
            "error", "No se encontró un registro SPF",
            why="Sin SPF, los receptores no pueden saber qué servidores están autorizados a enviar por este dominio.",
            fix="Publica un TXT en el dominio, por ejemplo: v=spf1 include:_spf.tu-proveedor.com -all")])
    if len(records) > 1:
        return build_result("SPF", " | ".join(records), [Finding(
            "error", f"Hay {len(records)} registros SPF (debe haber solo uno)",
            why="Con más de un registro SPF el resultado es un error permanente y la verificación falla.",
            fix="Combina todo en un único TXT que empiece con v=spf1.")])

    record = records[0].strip()
    terms, modifiers, parse_errors = parse_record(record)
    findings: list[Finding] = []
    for err in parse_errors:
        findings.append(Finding(
            "error", err,
            why="Un SPF con errores de sintaxis puede ser ignorado por el receptor.",
            fix="Corrige la sintaxis del registro."))
    for term in terms:
        err = _validate_term(term)
        if err:
            findings.append(Finding(
                "error", err,
                why="Un término inválido hace que el SPF completo falle.",
                fix="Corrige o elimina ese término."))
    if not findings:
        findings.append(Finding("ok", "Registro SPF encontrado y con sintaxis válida"))
    findings += _check_policy(terms, modifiers)
    findings += _check_deprecated(terms)
    findings += _check_lookups(domain, record, txt)
    return build_result("SPF", record, findings)


def check_spf(domain: str, txt: TxtLookup) -> ModuleResult:
    try:
        records = txt(domain)
    except DNSLookupError as exc:
        return build_result("SPF", None, [Finding(
            "error", "No se pudo consultar el DNS para el SPF", why=str(exc),
            fix="Revisa tu conexión o prueba con otro servidor DNS (--dns 8.8.8.8).")])
    return analyze_spf(domain, records, txt)
