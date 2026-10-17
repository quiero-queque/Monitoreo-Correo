import dns.resolver

def obtener_txt(nombre):
    try:
        respuesta = dns.resolver.resolve(nombre, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(r.strings).decode() for r in respuesta]

def obtener_spf(dominio):
    # TODO: devolver solo los textos de `dominio` que empiecen con "v=spf1"
    # Pasos: textos = obtener_txt(dominio); recorrer con for;
    #        si t.startswith("v=spf1"), agregarlo a una lista; devolver la lista.
    return []

def obtener_dmarc(dominio):
    # TODO: igual que obtener_spf, pero buscando en "_dmarc." + dominio
    #       y quedándote con los que empiecen con "v=DMARC1"
    return []

def parsear_etiquetas(texto):
    # TODO: convertir "v=DMARC1; p=reject; pct=100;"
    #       en {"v": "DMARC1", "p": "reject", "pct": "100"}
    resultado = {}
    for trozo in texto.split(";"):
        trozo = trozo.strip()
        # TODO 1: si "=" no está en trozo, usa `continue` para saltar al siguiente
        # TODO 2: clave, valor = trozo.split("=", 1)
        # TODO 3: resultado[clave.strip().lower()] = valor.strip()
    return resultado
