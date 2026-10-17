from modelos import Hallazgo
from dns_utils import parsear_etiquetas

def analizar_dmarc(registros):
    hallazgos = []

    if len(registros) == 0:
        # TODO: hallazgo "advertencia": sin DMARC, nadie le dice a
        #       Gmail/Outlook qué hacer con los correos falsos
        return hallazgos
    if len(registros) > 1:
        # TODO: hallazgo "error": con registros duplicados el receptor
        #       puede ignorar la política
        return hallazgos

    d = parsear_etiquetas(registros[0])   # d es un diccionario: d["p"], d.get("rua")...

    politica = d.get("p", "").lower()
    # TODO: según `politica`:
    #   ""           -> "error"        (p es obligatorio)
    #   "none"       -> "advertencia"  (solo observa, no protege)
    #   "quarantine" -> "ok"           (manda los fallidos a spam)
    #   "reject"     -> "ok"           (los rechaza: lo mejor)
    #   otro         -> "error"        (valor inválido)

    # TODO: si "rua" no está en d -> "advertencia" (no recibirán reportes de abuso)
    #       Pista: if "rua" not in d:

    # TODO: si "pct" está en d, convertirlo a número y avisar si es menor a 100:
    #   try:
    #       pct = int(d["pct"])
    #   except ValueError:
    #       ...  (hallazgo "error": el pct no es un número)
    #   Si pct < 100 -> "advertencia" (la política se aplica solo a una parte)

    return hallazgos
  
