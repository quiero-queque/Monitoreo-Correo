import pytest

from auditor.dns_utils import DNSLookupError


class FakeDNS:
    """DNS falso para tests: no toca internet."""

    def __init__(self, records=None, exists=True, fail=(), exists_error=False):
        self.records = {k.lower(): list(v) for k, v in (records or {}).items()}
        self._exists = exists
        self.fail = {f.lower() for f in fail}
        self.exists_error = exists_error

    def txt(self, name):
        if name.lower() in self.fail:
            raise DNSLookupError(f"tiempo de espera agotado consultando {name}")
        return list(self.records.get(name.lower(), []))

    def exists(self, name):
        if self.exists_error:
            raise DNSLookupError("tiempo de espera agotado")
        return self._exists


@pytest.fixture
def make_dns():
    return FakeDNS


def levels(result):
    return [f.level for f in result.findings]


def messages(result):
    return " | ".join(f.message for f in result.findings)
