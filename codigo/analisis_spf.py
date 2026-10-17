from modelos import Hallazgo

def analizar_spf(registros):
    hallazgos = []

    if len(registros) == 0:
        hallazgos.append(Hallazgo("advertencia",
            "El dominio no tiene registro SPF",
            "Sin SPF, cualquiera puede enviar correo haciéndose pasar por este dominio.",
            "Publicar un registro TXT que empiece con v=spf1."))
        return hallazgos

    if len(registros) > 1:
        # TODO: agregar un hallazgo "error": solo puede haber UN registro SPF
        #       (copia el formato del hallazgo de arriba)
        return hallazgos

    tokens = registros[0].split()

    # TODO: si algún token empieza con "redirect=", agregar un hallazgo "ok"
    #       (la política está en otro dominio) y hacer return hallazgos
    #       Pista: for t in tokens: if t.startswith("redirect="): ...

    ultimo = tokens[-1]
    # TODO: según `ultimo`, agregar el hallazgo que corresponda:
    #   "+all" -> "error"        (acepta a cualquiera: es como no tener SPF)
    #   "?all" -> "advertencia"  (neutral: no protege)
    #   "~all" -> "ok"           (menciona que "-all" es más estricto)
    #   "-all" -> "ok"           (rechaza a los no autorizados)
    #   otro   -> "advertencia"  (no termina con una regla "all")

    return hallazgos
