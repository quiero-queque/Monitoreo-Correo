from dns_utils import obtener_spf, obtener_dmarc, parsear_etiquetas

print(obtener_spf("gmail.com"))
print(obtener_dmarc("gmail.com"))
print(parsear_etiquetas("v=DMARC1; p=reject; pct=100;"))
