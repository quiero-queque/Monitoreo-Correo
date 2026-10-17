from analisis_dmarc import analizar_dmarc

def sev(hallazgos):
    return [h.severidad for h in hallazgos]

def test_sin_dmarc():
    assert "advertencia" in sev(analizar_dmarc([]))

def test_none_es_advertencia():
    assert "advertencia" in sev(analizar_dmarc(["v=DMARC1; p=none; rua=mailto:a@b.cl"]))

def test_sin_p_es_error():
    assert "error" in sev(analizar_dmarc(["v=DMARC1; rua=mailto:a@b.cl"]))

def test_reject_completo_sin_problemas():
    r = sev(analizar_dmarc(["v=DMARC1; p=reject; rua=mailto:a@b.cl"]))
    assert "error" not in r and "advertencia" not in r
