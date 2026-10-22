from auditor.dmarc import check_dmarc
from tests.conftest import messages


def dmarc(make_dns, *records):
    dns = make_dns({"_dmarc.ej.cl": list(records)})
    return check_dmarc("ej.cl", dns.txt)


def test_sin_dmarc_es_error(make_dns):
    r = dmarc(make_dns)
    assert r.status == "error"
    assert "No se encontró" in messages(r)


def test_dos_registros_es_error(make_dns):
    assert dmarc(make_dns, "v=DMARC1; p=none", "v=DMARC1; p=reject").status == "error"


def test_reject_con_rua_es_ok(make_dns):
    r = dmarc(make_dns, "v=DMARC1; p=reject; rua=mailto:dmarc@ej.cl")
    assert r.status == "ok"


def test_quarantine_es_ok(make_dns):
    assert dmarc(make_dns, "v=DMARC1; p=quarantine; rua=mailto:a@ej.cl").status == "ok"


def test_none_es_advertencia(make_dns):
    r = dmarc(make_dns, "v=DMARC1; p=none; rua=mailto:a@ej.cl")
    assert r.status == "warning"
    assert "p=none" in messages(r)


def test_politica_invalida_es_error(make_dns):
    assert dmarc(make_dns, "v=DMARC1; p=bloquear").status == "error"


def test_sin_p_es_error(make_dns):
    assert dmarc(make_dns, "v=DMARC1; rua=mailto:a@ej.cl").status == "error"


def test_sin_rua_es_advertencia(make_dns):
    r = dmarc(make_dns, "v=DMARC1; p=reject")
    assert r.status == "warning"
    assert "rua" in messages(r)


def test_rua_invalida_es_advertencia(make_dns):
    assert dmarc(make_dns, "v=DMARC1; p=reject; rua=dmarc@ej.cl").status == "warning"


def test_pct_menor_a_100_es_advertencia(make_dns):
    r = dmarc(make_dns, "v=DMARC1; p=reject; pct=50; rua=mailto:a@ej.cl")
    assert r.status == "warning"


def test_sp_none_con_p_reject_es_advertencia(make_dns):
    r = dmarc(make_dns, "v=DMARC1; p=reject; sp=none; rua=mailto:a@ej.cl")
    assert r.status == "warning"


def test_alineacion_strict_se_informa(make_dns):
    r = dmarc(make_dns, "v=DMARC1; p=reject; adkim=s; aspf=r; rua=mailto:a@ej.cl")
    assert "DKIM strict, SPF relaxed" in messages(r)


def test_alineacion_por_defecto_es_relaxed(make_dns):
    r = dmarc(make_dns, "v=DMARC1; p=reject; rua=mailto:a@ej.cl")
    assert "DKIM relaxed, SPF relaxed" in messages(r)


def test_espacios_y_mayusculas_no_rompen(make_dns):
    r = dmarc(make_dns, "v=DMARC1 ;  P=Reject ; RUA=mailto:a@ej.cl")
    assert r.status == "ok"
