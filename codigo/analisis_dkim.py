import base64
from cryptography.hazmat.primitives.serialization import load_der_public_key
from modelos import Hallazgo
from dns_utils import parsear_etiquetas

def tamano_clave(p):
    """Bits de una clave RSA en base64, o None si no se puede leer."""
    try:
        clave = load_der_public_key(base64.b64decode(p.replace(" ", "")))
        return clave.key_size
    except Exception:
        return None

def analizar_dkim(registros, selector):
    hallazgos = []

    if len(registros) == 0:
        # TODO: hallazgo "advertencia" (no error): no se encontró DKIM con el
        #       selector `selector`. Es advertencia porque el dominio podría
        #       usar otro selector.
        return hallazgos

    d = parsear_etiquetas(registros[0])
    p = d.get("p", "")

    # TODO: si p == "" -> "error" (la clave fue revocada o falta) y return
    # TODO: si d.get("k") == "ed25519" -> "ok" y return (no tiene tamaño RSA)
    # TODO: bits = tamano_clave(p) y según bits:
    #   None        -> "advertencia" (no se pudo leer la clave)
    #   menos 1024  -> "error"
    #   1024        -> "advertencia" (se recomienda 2048)
    #   2048 o más  -> "ok"

    return hallazgos
