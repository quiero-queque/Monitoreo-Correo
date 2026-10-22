"""Orquesta la auditoría completa de un dominio."""
from __future__ import annotations

from .dkim import check_dkim
from .dmarc import check_dmarc
from .dns_utils import DnsClient, DNSLookupError
from .models import Finding, build_result
from .scoring import AuditReport, build_report
from .spf import check_spf


def audit_domain(domain: str, selectors: list[str] | None = None, dns=None) -> AuditReport:
    """`dns` es cualquier objeto con .txt(nombre) y .exists(nombre) (los tests usan uno falso)."""
    dns = dns or DnsClient()
    try:
        exists = dns.exists(domain)
    except DNSLookupError as exc:
        return build_report(domain, [build_result("DNS", None, [Finding(
            "error", "No se pudo consultar el DNS", why=str(exc),
            fix="Revisa tu conexión o prueba con otro servidor DNS (--dns 8.8.8.8).")])])
    if not exists:
        return build_report(domain, [build_result("Dominio", None, [Finding(
            "error", "El dominio no existe",
            why="El DNS respondió que el nombre no existe (NXDOMAIN).",
            fix="Revisa que esté bien escrito.")])])
    results = [
        check_spf(domain, dns.txt),
        check_dmarc(domain, dns.txt),
        check_dkim(domain, dns.txt, selectors),
    ]
    return build_report(domain, results)
