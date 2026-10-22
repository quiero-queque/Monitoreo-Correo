"""Módulo DMARC (RFC 7489 / DMARCbis RFC 9989).

Valida: existencia, un solo registro, política p=, sp=, pct=, rua= y modos de alineación.
La alineación solo puede evaluarse como *configuración* (adkim/aspf): comprobar si un
correo concreto está alineado requiere un correo real.
"""
from __future__ import annotations

import re

from .dns_utils import DNSLookupError
from .models import Finding, ModuleResult, build_result
from .spf import TxtLookup

POLICIES = {"none", "quarantine", "reject"}
_VERSION_RE = re.compile(r"^\s*v\s*=\s*dmarc1\s*(;|$)", re.IGNORECASE)
_MAILTO_RE = re.compile(r"^mailto:[^@\s]+@[^@\s]+\.[^@\s]+$", re.IGNORECASE)


def find_dmarc_records(txt_records: list[str]) -> list[str]:
    return [r for r in txt_records if _VERSION_RE.match(r)]


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags.setdefault(key.strip().lower(), value.strip())
    return tags


def analyze_dmarc(domain: str, txt_records: list[str]) -> ModuleResult:
    records = find_dmarc_records(txt_records)
    if not records:
        fix = f"Publica un TXT en _dmarc.{domain}, por ejemplo: v=DMARC1; p=none; rua=mailto:dmarc@{domain}"
        why = ("Sin DMARC, los receptores no saben qué hacer con los correos que fallan SPF/DKIM, "
               "y Google/Yahoo lo exigen a quienes envían correo masivo.")
        if domain.count(".") >= 2:
            why += " (Si es un subdominio, la política puede heredarse del dominio principal.)"
        return build_result("DMARC", None, [Finding("error", "No se encontró un registro DMARC", why=why, fix=fix)])
    if len(records) > 1:
        return build_result("DMARC", " | ".join(records), [Finding(
            "error", f"Hay {len(records)} registros DMARC (debe haber solo uno)",
            why="Con más de un registro DMARC, los receptores lo ignoran.",
            fix="Deja un único TXT en _dmarc con v=DMARC1.")])

    record = records[0].strip()
    tags = parse_tags(record)
    findings: list[Finding] = [Finding("ok", "Registro DMARC encontrado")]

    # --- Política p= ---
    p = tags.get("p", "").lower()
    if not p:
        findings.append(Finding(
            "error", "Falta la política (p=)",
            why="p= es obligatorio: sin él el registro no es válido.",
            fix="Agrega p=none, p=quarantine o p=reject."))
    elif p not in POLICIES:
        findings.append(Finding(
            "error", f"Política p={p} no válida",
            why="Solo se permiten none, quarantine y reject.",
            fix="Usa p=none, p=quarantine o p=reject."))
    elif p == "none":
        findings.append(Finding(
            "warning", "Política p=none: solo observa, no protege",
            why="Los correos falsificados siguen llegando; DMARC solo genera reportes.",
            fix="Revisa los reportes y, cuando todo esté en orden, sube a p=quarantine y luego p=reject."))
    elif p == "quarantine":
        findings.append(Finding("ok", "Política p=quarantine: los correos que fallan van a spam"))
    else:
        findings.append(Finding("ok", "Política p=reject: los correos que fallan son rechazados"))

    # --- Política de subdominios sp= ---
    sp = tags.get("sp", "").lower()
    if sp:
        if sp not in POLICIES:
            findings.append(Finding(
                "warning", f"Política de subdominios sp={sp} no válida",
                why="Un valor inválido se ignora.", fix="Usa none, quarantine o reject."))
        elif sp == "none" and p in ("quarantine", "reject"):
            findings.append(Finding(
                "warning", "Los subdominios quedan sin protección (sp=none)",
                why="Un atacante podría suplantar subdominios aunque el dominio principal esté protegido.",
                fix="Quita sp= o iguálalo a p=."))

    # --- Porcentaje pct= ---
    if "pct" in tags:
        try:
            pct = int(tags["pct"])
        except ValueError:
            pct = -1
        if not 0 <= pct <= 100:
            findings.append(Finding(
                "warning", f"Valor pct={tags['pct']} no válido",
                why="pct debe ser un entero entre 0 y 100.", fix="Corrige o elimina pct."))
        elif pct < 100:
            findings.append(Finding(
                "warning", f"La política solo se aplica al {pct}% de los correos (pct={pct})",
                why="El resto de los correos que fallan se tratan como si la política fuera más débil. "
                    "Además, DMARCbis (RFC 9989) eliminó pct: verifiquen en el RFC cómo lo reemplaza.",
                fix="Cuando termines la etapa de prueba, quita pct o ponlo en 100."))

    # --- Reportes rua= ---
    rua = tags.get("rua", "")
    if not rua:
        findings.append(Finding(
            "warning", "No hay dirección para reportes (rua=)",
            why="Sin reportes no puedes ver quién envía correo en nombre de tu dominio.",
            fix=f"Agrega rua=mailto:dmarc@{domain}"))
    else:
        bad = [a.strip() for a in rua.split(",") if not _MAILTO_RE.match(a.strip())]
        if bad:
            findings.append(Finding(
                "warning", f"Dirección rua inválida: {', '.join(bad)}",
                why="Las direcciones de reporte deben tener el formato mailto:correo@dominio.",
                fix="Usa rua=mailto:correo@dominio"))
        else:
            findings.append(Finding("ok", "Recibe reportes agregados (rua=)"))

    # --- Alineación adkim / aspf ---
    modes = {}
    for key, label in (("adkim", "DKIM"), ("aspf", "SPF")):
        value = tags.get(key, "r").lower()
        if value not in ("r", "s"):
            findings.append(Finding(
                "warning", f"Valor {key}={value} no válido",
                why="Solo se permite r (relaxed) o s (strict).", fix=f"Usa {key}=r o {key}=s."))
            value = "r"
        modes[label] = "strict" if value == "s" else "relaxed"
    findings.append(Finding(
        "info", f"Alineación: DKIM {modes['DKIM']}, SPF {modes['SPF']}",
        why="Relaxed acepta subdominios del mismo dominio; strict exige que el dominio sea idéntico al del 'De:'."))

    return build_result("DMARC", record, findings)


def check_dmarc(domain: str, txt: TxtLookup) -> ModuleResult:
    try:
        records = txt(f"_dmarc.{domain}")
    except DNSLookupError as exc:
        return build_result("DMARC", None, [Finding(
            "error", "No se pudo consultar el DNS para DMARC", why=str(exc),
            fix="Revisa tu conexión o prueba con otro servidor DNS (--dns 8.8.8.8).")])
    return analyze_dmarc(domain, records)
