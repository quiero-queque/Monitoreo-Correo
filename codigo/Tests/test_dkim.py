from analisis_dkim import analizar_dkim

def sev(hallazgos):
    return [h.severidad for h in hallazgos]

def test_sin_registro_es_advertencia():
    assert "advertencia" in sev(analizar_dkim([], "google"))

def test_clave_vacia_es_error():
    assert "error" in sev(analizar_dkim(["v=DKIM1; k=rsa; p="], "google"))
