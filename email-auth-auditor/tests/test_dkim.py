import base64

from auditor.dkim import check_dkim
from tests.conftest import messages


def key(n_bytes):
    """Clave falsa con el largo en bytes de una clave real (162 = RSA 1024, 294 = RSA 2048)."""
    return base64.b64encode(b"A" * n_bytes).decode()


def dkim(make_dns, records, selectors=None, **kw):
    dns = make_dns(records, **kw)
    return check_dkim("ej.cl", dns.txt, selectors)


def test_selector_valido_rsa_2048(make_dns):
    r = dkim(make_dns, {"google._domainkey.ej.cl": [f"v=DKIM1; k=rsa; p={key(294)}"]}, ["google"])
    assert r.status == "ok"
    assert "2048" in messages(r)
    assert r.record == "google._domainkey.ej.cl"


def test_encuentra_selector_comun_sin_indicarlo(make_dns):
    r = dkim(make_dns, {"selector1._domainkey.ej.cl": [f"v=DKIM1; p={key(294)}"]})
    assert r.status == "ok"


def test_sin_selectores_comunes_es_advertencia_honesta(make_dns):
    r = dkim(make_dns, {})
    assert r.status == "warning"
    assert "No encontramos DKIM con los selectores comunes" in messages(r)
    assert "NO significa" in r.findings[0].why


def test_selector_indicado_inexistente_es_advertencia(make_dns):
    r = dkim(make_dns, {}, ["miselector"])
    assert r.status == "warning"
    assert "miselector" in messages(r)


def test_sin_p_es_error(make_dns):
    r = dkim(make_dns, {"s1._domainkey.ej.cl": ["v=DKIM1; k=rsa"]}, ["s1"])
    assert r.status == "error"


def test_p_vacio_es_clave_revocada(make_dns):
    r = dkim(make_dns, {"s1._domainkey.ej.cl": ["v=DKIM1; p="]}, ["s1"])
    assert r.status == "warning"
    assert "revocada" in messages(r)


def test_rsa_1024_es_advertencia(make_dns):
    r = dkim(make_dns, {"s1._domainkey.ej.cl": [f"v=DKIM1; p={key(162)}"]}, ["s1"])
    assert r.status == "warning"


def test_rsa_512_es_error(make_dns):
    r = dkim(make_dns, {"s1._domainkey.ej.cl": [f"v=DKIM1; p={key(94)}"]}, ["s1"])
    assert r.status == "error"


def test_base64_invalido_es_error(make_dns):
    r = dkim(make_dns, {"s1._domainkey.ej.cl": ["v=DKIM1; p=!!!no-es-base64!!!"]}, ["s1"])
    assert r.status == "error"


def test_modo_de_prueba_es_advertencia(make_dns):
    r = dkim(make_dns, {"s1._domainkey.ej.cl": [f"v=DKIM1; t=y; p={key(294)}"]}, ["s1"])
    assert r.status == "warning"


def test_ed25519_es_valido(make_dns):
    r = dkim(make_dns, {"s1._domainkey.ej.cl": [f"v=DKIM1; k=ed25519; p={key(32)}"]}, ["s1"])
    assert r.status == "ok"


def test_version_invalida_es_error(make_dns):
    r = dkim(make_dns, {"s1._domainkey.ej.cl": [f"v=DKIM2; p={key(294)}"]}, ["s1"])
    assert r.status == "error"


def test_fallo_dns_en_un_selector_no_rompe(make_dns):
    r = dkim(make_dns, {"s2._domainkey.ej.cl": [f"v=DKIM1; p={key(294)}"]},
             fail=["s1._domainkey.ej.cl"])
    assert r.status == "ok"
    assert "fallaron" in messages(r)
