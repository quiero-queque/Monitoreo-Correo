from dns_utils import parsear_etiquetas

def test_parsear_dmarc():
    assert parsear_etiquetas("v=DMARC1; p=reject; pct=100;") == {
        "v": "DMARC1", "p": "reject", "pct": "100"}

def test_parsear_clave_con_igual():
    assert parsear_etiquetas("v=DKIM1; p=AAAA==")["p"] == "AAAA=="
