from auditor.spf import check_spf
from tests.conftest import levels, messages


def spf(make_dns, domain_records, extra=None):
    records = {"ej.cl": domain_records}
    records.update(extra or {})
    dns = make_dns(records)
    return check_spf("ej.cl", dns.txt)


def test_sin_spf_es_error(make_dns):
    r = spf(make_dns, ["hola mundo"])
    assert r.status == "error"
    assert "No se encontró" in messages(r)


def test_dos_registros_spf_es_error(make_dns):
    r = spf(make_dns, ["v=spf1 -all", "v=spf1 ~all"])
    assert r.status == "error"
    assert "2 registros" in messages(r)


def test_menos_all_es_ok(make_dns):
    r = spf(make_dns, ["v=spf1 ip4:203.0.113.5 -all"])
    assert r.status == "ok"
    assert "-all" in messages(r)


def test_tilde_all_es_aceptable(make_dns):
    r = spf(make_dns, ["v=spf1 ip4:203.0.113.0/24 ~all"])
    assert r.status == "ok"
    assert "info" in levels(r)


def test_mas_all_es_error_grave(make_dns):
    r = spf(make_dns, ["v=spf1 +all"])
    assert r.status == "error"
    assert "+all" in messages(r)


def test_all_sin_simbolo_es_mas_all(make_dns):
    assert spf(make_dns, ["v=spf1 all"]).status == "error"


def test_interrogacion_all_es_error(make_dns):
    assert spf(make_dns, ["v=spf1 ?all"]).status == "error"


def test_sin_all_es_advertencia(make_dns):
    r = spf(make_dns, ["v=spf1 ip4:203.0.113.5"])
    assert r.status == "warning"


def test_mecanismo_despues_de_all_es_advertencia(make_dns):
    r = spf(make_dns, ["v=spf1 -all ip4:203.0.113.5"])
    assert r.status == "warning"


def test_ip_invalida_es_error(make_dns):
    r = spf(make_dns, ["v=spf1 ip4:999.1.1.1 -all"])
    assert r.status == "error"


def test_mecanismo_desconocido_es_error(make_dns):
    r = spf(make_dns, ["v=spf1 foo:bar -all"])
    assert r.status == "error"


def test_ptr_es_advertencia(make_dns):
    r = spf(make_dns, ["v=spf1 ptr -all"])
    assert r.status == "warning"


def test_include_se_sigue_y_se_cuenta(make_dns):
    r = spf(make_dns, ["v=spf1 include:_spf.google.com ~all"],
            {"_spf.google.com": ["v=spf1 ip4:1.2.3.4 include:b.google.com ~all"],
             "b.google.com": ["v=spf1 ip4:5.6.7.8 ~all"]})
    assert r.status == "ok"
    assert "Usa 2 de 10" in messages(r)


def test_mas_de_10_lookups_es_error(make_dns):
    includes = " ".join(f"include:i{n}.ej.cl" for n in range(11))
    extra = {f"i{n}.ej.cl": ["v=spf1 ip4:1.2.3.4 -all"] for n in range(11)}
    r = spf(make_dns, [f"v=spf1 {includes} -all"], extra)
    assert r.status == "error"
    assert "límite" in messages(r)


def test_exactamente_10_lookups_es_advertencia(make_dns):
    includes = " ".join(f"include:i{n}.ej.cl" for n in range(10))
    extra = {f"i{n}.ej.cl": ["v=spf1 ip4:1.2.3.4 -all"] for n in range(10)}
    r = spf(make_dns, [f"v=spf1 {includes} -all"], extra)
    assert r.status == "warning"


def test_include_sin_spf_es_error(make_dns):
    r = spf(make_dns, ["v=spf1 include:roto.ej.cl -all"])
    assert r.status == "error"
    assert "roto.ej.cl" in messages(r)


def test_bucle_de_includes_no_cuelga(make_dns):
    r = spf(make_dns, ["v=spf1 include:a.ej.cl -all"],
            {"a.ej.cl": ["v=spf1 include:ej.cl -all"]})
    assert r.status == "error"
    assert "Bucle" in messages(r)


def test_redirect_se_acepta(make_dns):
    r = spf(make_dns, ["v=spf1 redirect=_spf.ej.cl"],
            {"_spf.ej.cl": ["v=spf1 ip4:1.2.3.4 -all"]})
    assert r.status == "ok"


def test_fallo_de_dns_no_rompe(make_dns):
    dns = make_dns({}, fail=["ej.cl"])
    r = check_spf("ej.cl", dns.txt)
    assert r.status == "error"
    assert "No se pudo consultar" in messages(r)
