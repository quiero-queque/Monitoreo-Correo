import base64
import json

import pytest

from auditor.audit import audit_domain
from auditor.cli import main, normalize_domain

KEY = base64.b64encode(b"A" * 294).decode()


def buen_dominio(spf="v=spf1 ip4:203.0.113.5 -all", dmarc="v=DMARC1; p=reject; rua=mailto:d@ej.cl"):
    return {
        "ej.cl": [spf],
        "_dmarc.ej.cl": [dmarc],
        "google._domainkey.ej.cl": [f"v=DKIM1; k=rsa; p={KEY}"],
    }


def test_dominio_bien_configurado_aprueba(make_dns):
    report = audit_domain("ej.cl", None, make_dns(buen_dominio()))
    assert report.verdict == "ok"
    assert report.label == "Aprobado"


def test_dkim_no_encontrado_da_advertencias(make_dns):
    records = buen_dominio()
    del records["google._domainkey.ej.cl"]
    report = audit_domain("ej.cl", None, make_dns(records))
    assert report.verdict == "warning"


def test_spf_mas_all_da_errores(make_dns):
    report = audit_domain("ej.cl", None, make_dns(buen_dominio(spf="v=spf1 +all")))
    assert report.verdict == "error"
    assert report.label == "Con errores"


def test_dmarc_none_da_advertencias(make_dns):
    report = audit_domain("ej.cl", None, make_dns(buen_dominio(dmarc="v=DMARC1; p=none; rua=mailto:d@ej.cl")))
    assert report.verdict == "warning"


def test_dominio_inexistente(make_dns):
    report = audit_domain("noexiste.cl", None, make_dns({}, exists=False))
    assert report.verdict == "error"
    assert "no existe" in report.results[0].findings[0].message


def test_fallo_dns_general(make_dns):
    report = audit_domain("ej.cl", None, make_dns({}, exists_error=True))
    assert report.verdict == "error"


@pytest.mark.parametrize("entrada,esperado", [
    ("usm.cl", "usm.cl"),
    ("USM.CL", "usm.cl"),
    ("https://www.usm.cl/ruta", "www.usm.cl"),
    ("alguien@usm.cl", "usm.cl"),
    ("usm.cl.", "usm.cl"),
])
def test_normalize_domain(entrada, esperado):
    assert normalize_domain(entrada) == esperado


@pytest.mark.parametrize("malo", ["", "sin punto", "a..b", "-x.cl", "http://"])
def test_normalize_domain_invalido(malo):
    with pytest.raises(ValueError):
        normalize_domain(malo)


def test_cli_json(make_dns, capsys):
    code = main(["ej.cl", "--json"], dns=make_dns(buen_dominio()))
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data[0]["domain"] == "ej.cl"
    assert data[0]["verdict"] == "ok"
    assert [r["name"] for r in data[0]["results"]] == ["SPF", "DMARC", "DKIM"]


def test_cli_codigo_de_salida_con_errores(make_dns, capsys):
    code = main(["ej.cl", "--json"], dns=make_dns(buen_dominio(spf="v=spf1 +all")))
    capsys.readouterr()
    assert code == 1


def test_cli_salida_de_texto(make_dns, capsys):
    code = main(["ej.cl", "--selector", "google"], dns=make_dns(buen_dominio()))
    out = capsys.readouterr().out
    assert code == 0
    assert "Aprobado" in out and "SPF" in out and "DMARC" in out and "DKIM" in out


def test_cli_dominio_invalido(capsys):
    assert main(["no es un dominio"]) == 2
