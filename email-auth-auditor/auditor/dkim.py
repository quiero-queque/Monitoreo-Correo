"""Módulo DKIM (RFC 6376).

Limitación importante: DKIM no se puede "descubrir" sin conocer el selector.
Por eso se consulta el selector indicado o, si no hay, una lista de selectores comunes.
Aquí solo se valida la clave pública publicada en DNS; verificar una firma real
requiere un correo real.
"""
from __future__ import annotations

import base64
import binascii
from concurrent.futures import ThreadPoolExecutor

from .dmarc import parse_tags
from .dns_utils import DNSLookupError
from .models import Finding, ModuleResult, build_result
from .spf import TxtLookup

COMMON_SELECTORS = [
    "google", "selector1", "selector2", "s1", "s2",
    "k1", "k2", "default", "dkim", "mail", "smtp", "mandrill",
]


def _rsa_size(p_b64: str) -> tuple[str, int | None]:
    """Estima el tamaño de una clave RSA por el largo del DER. Devuelve (nivel, bits_aprox)."""
    try:
        raw = base64.b64decode("".join(p_b64.split()), validate=True)
    except (binascii.Error, ValueError):
        return "malformed", None
    if len(raw) < 130:
        return "error", 512
    if len(raw) < 230:
        return "warning", 1024
    return "ok", 2048 if len(raw) < 450 else 4096


def analyze_selector(selector: str, domain: str, records: list[str]) -> tuple[str, list[Finding]]:
    """Analiza el TXT de un selector. Devuelve (nombre_dns, hallazgos)."""
    name = f"{selector}._domainkey.{domain}"
    record = next((r for r in records if "v=dkim1" in r.lower().replace(" ", "")), records[0])
    tags = parse_tags(record)
    prefix = f"Selector '{selector}': "
    findings: list[Finding] = []

    version = tags.get("v")
    if version is not None and version.upper() != "DKIM1":
        findings.append(Finding(
            "error", prefix + f"versión v={version} no válida",
            why="El valor de v= debe ser DKIM1.", fix="Usa v=DKIM1."))

    if "p" not in tags:
        findings.append(Finding(
            "error", prefix + "el registro no tiene clave pública (p=)",
            why="Sin la clave pública el receptor no puede verificar las firmas.",
            fix="Publica el registro completo que entrega tu proveedor de correo."))
        return name, findings
    if tags["p"] == "":
        findings.append(Finding(
            "warning", prefix + "la clave está revocada (p= vacío)",
            why="Los correos firmados con este selector fallarán la verificación DKIM.",
            fix="Si no era intencional, publica de nuevo la clave pública."))
        return name, findings

    key_type = tags.get("k", "rsa").lower()
    key_info = ""
    if key_type == "rsa":
        level, bits = _rsa_size(tags["p"])
        if level == "malformed":
            findings.append(Finding(
                "error", prefix + "la clave pública está mal formada (base64 inválido)",
                why="Si la clave se cortó o tiene caracteres extra, DKIM falla.",
                fix="Copia de nuevo el registro completo desde tu proveedor."))
            return name, findings
        key_info = f" (RSA ~{bits} bits)"
        if level == "error":
            findings.append(Finding(
                "error", prefix + f"clave RSA muy débil (~{bits} bits)",
                why="Una clave tan corta puede ser rota; Gmail y otros la rechazan.",
                fix="Genera una clave RSA de 2048 bits."))
        elif level == "warning":
            findings.append(Finding(
                "warning", prefix + f"clave RSA de ~{bits} bits",
                why="1024 bits se considera débil hoy; se recomienda 2048.",
                fix="Genera una clave de 2048 bits y publícala con un selector nuevo."))
    elif key_type == "ed25519":
        key_info = " (Ed25519)"
    else:
        findings.append(Finding(
            "error", prefix + f"tipo de clave k={key_type} no soportado",
            why="DKIM solo define rsa y ed25519.", fix="Usa k=rsa o k=ed25519."))

    if "y" in tags.get("t", "").lower().split(":"):
        findings.append(Finding(
            "warning", prefix + "está en modo de prueba (t=y)",
            why="Algunos receptores ignoran los fallos de un selector en modo de prueba.",
            fix="Quita t=y cuando termines de probar."))

    if not any(f.level in ("error", "warning") for f in findings):
        findings.insert(0, Finding("ok", prefix + f"clave pública encontrada y válida{key_info}"))
    return name, findings


def check_dkim(domain: str, txt: TxtLookup, selectors: list[str] | None = None) -> ModuleResult:
    explicit = bool(selectors)
    chosen = list(dict.fromkeys(s.strip() for s in (selectors or COMMON_SELECTORS) if s.strip()))

    def probe(selector: str):
        try:
            return selector, txt(f"{selector}._domainkey.{domain}"), None
        except DNSLookupError as exc:
            return selector, [], str(exc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        probes = list(pool.map(probe, chosen))

    findings: list[Finding] = []
    found_names: list[str] = []
    missing: list[str] = []
    dns_errors = 0
    for selector, records, error in probes:
        if error:
            dns_errors += 1
        if not records:
            missing.append(selector)
            continue
        name, selector_findings = analyze_selector(selector, domain, records)
        found_names.append(name)
        findings += selector_findings

    if explicit:
        for selector in missing:
            findings.append(Finding(
                "warning", f"No se encontró DKIM en el selector '{selector}'",
                why=f"No existe un TXT en {selector}._domainkey.{domain}. Puede que el selector esté mal escrito "
                    "o que ese proveedor aún no esté configurado.",
                fix="Revisa el selector en el panel de tu proveedor de correo o en el campo s= de la "
                    "cabecera DKIM-Signature de un correo real."))
    elif not found_names:
        findings.append(Finding(
            "warning", "No encontramos DKIM con los selectores comunes probados",
            why="DKIM no puede descubrirse sin saber el selector: el dominio podría tener DKIM con un selector "
                "que no probamos. Esto NO significa necesariamente que no tenga DKIM.",
            fix="Averigua el selector (panel del proveedor o campo s= de DKIM-Signature en un correo real) "
                "y ejecuta de nuevo con --selector. Probados: " + ", ".join(chosen) + "."))
    if dns_errors:
        findings.append(Finding(
            "info", f"{dns_errors} consulta(s) DNS fallaron o agotaron el tiempo",
            why="Los resultados de DKIM podrían estar incompletos.",
            fix="Vuelve a ejecutar o prueba con otro servidor DNS (--dns 8.8.8.8)."))

    return build_result("DKIM", ", ".join(found_names) or None, findings)
