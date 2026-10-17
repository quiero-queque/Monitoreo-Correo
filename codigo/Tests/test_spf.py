from analisis_spf import analizar_spf

def sev(hallazgos):
    return [h.severidad for h in hallazgos]

def test_sin_spf():
    assert "advertencia" in sev(analizar_spf([]))

def test_mas_all():
    assert "error" in sev(analizar_spf(["v=spf1 +all"]))

def test_doble_spf():
    assert "error" in sev(analizar_spf(["v=spf1 -all", "v=spf1 ~all"]))

def test_menos_all_sin_problemas():
    r = sev(analizar_spf(["v=spf1 ip4:1.2.3.4 -all"]))
    assert "error" not in r and "advertencia" not in r

def test_redirect_sin_advertencia():
    assert "advertencia" not in sev(analizar_spf(["v=spf1 redirect=_spf.ejemplo.com"]))
