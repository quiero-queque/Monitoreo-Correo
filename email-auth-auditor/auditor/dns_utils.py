"""Consultas DNS con dnspython.

Los módulos no usan dnspython directamente: reciben una función `txt(nombre)`.
Así los tests pueden inyectar registros falsos sin tocar internet.
"""
from __future__ import annotations

import dns.exception
import dns.resolver


class DNSLookupError(Exception):
    """No se pudo completar una consulta DNS (timeout, SERVFAIL, etc.)."""


class DnsClient:
    def __init__(self, nameservers: list[str] | None = None, timeout: float = 5.0):
        try:
            self._resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration:
            self._resolver = dns.resolver.Resolver(configure=False)
            self._resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    def _query(self, name: str) -> tuple[bool, list[str]]:
        """Devuelve (el_nombre_existe, registros_TXT)."""
        try:
            answer = self._resolver.resolve(name, "TXT")
        except dns.resolver.NXDOMAIN:
            return False, []
        except dns.resolver.NoAnswer:
            return True, []
        except dns.exception.Timeout as exc:
            raise DNSLookupError(f"tiempo de espera agotado consultando {name}") from exc
        except dns.exception.DNSException as exc:
            raise DNSLookupError(f"error DNS ({exc.__class__.__name__}) consultando {name}") from exc
        # Un TXT puede venir partido en varias cadenas de 255 bytes: se unen.
        return True, [b"".join(r.strings).decode("utf-8", errors="replace") for r in answer]

    def txt(self, name: str) -> list[str]:
        """Registros TXT de `name`. Lista vacía si no hay (o el nombre no existe)."""
        return self._query(name)[1]

    def exists(self, name: str) -> bool:
        """False solo si DNS responde NXDOMAIN (el dominio no existe)."""
        return self._query(name)[0]
