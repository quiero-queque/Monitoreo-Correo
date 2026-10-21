from modelos import Hallazgo

# Formas posibles de la regla final de un SPF. "all" a secas equivale a "+all"
REGLAS_ALL = ("+all", "-all", "~all", "?all", "all")  # constantes


def _usa_ptr(tokens):  # función interna (el _ avisa que solo se usa en este archivo), recibe la lista de palabras del SPF
    """True si algún mecanismo es 'ptr' (con o sin calificador +, -, ~, ?)."""  # descripcion
    for t in tokens: #recorre cada palabra
        mecanismo = t.lstrip("+-~?")  # lstrip quita esos símbolos del lado izquierdo: "-ptr" pasa a "ptr"
        if mecanismo == "ptr" or mecanismo.startswith("ptr:"):  # ptr puede venir solo o con dominio ("ptr:ejemplo.com")
            return True  # encontró uno, no hace falta seguir buscando
    return False  # recorrió todo y no apareció ptr


def analizar_spf(registros):  # recibe la lista de SPF que devolvió obtener_spf
    """`registros` es la lista de textos que empiezan con v=spf1. Devuelve una lista de Hallazgo."""  # descripcion
    hallazgos = []  # lista vacía donde se irán juntando los hallazgos

    # Caso 1: no hay SPF 
    if len(registros) == 0:  # len() cuenta los elementos: cero significa que el dominio no tiene SPF
        hallazgos.append(Hallazgo(  # crea un Hallazgo y lo agrega a la lista (siempre son 4 datos, en este orden)
            "advertencia",  # 1 severidad
            "El dominio no tiene registro SPF",  #  mensaje: qué se encontró
            "Sin SPF, cualquiera puede enviar correo haciéndose pasar por este dominio.",  # 3 por qué importa
            "Publicar un registro TXT que empiece con v=spf1."))  # 4 como solucionar
        return hallazgos  # termina porque no tiene sentido analizar algo que no existe

    # Caso 2: hay más de uno
    if len(registros) > 1:  # más de un SPF en el mismo dominio
        hallazgos.append(Hallazgo(
            "error",  # severidad: es un error porque el estándar solo permite uno
            f"El dominio tiene {len(registros)} registros SPF",  # f-string: lo que va entre {} se reemplaza por su valor 
            "Solo puede haber uno. Con varios, los servidores receptores descartan el SPF "
            "y el dominio queda sin protección.",  # por qué importa
            "Unir todos los servidores autorizados en un único registro v=spf1."))  # cómo arreglarlo
        return hallazgos  # termina aquí con duplicados no se puede analizar cuál es el correcto

    tokens = registros[0].lower().split()   # toma el único SPF, lo pasa a minúsculas y lo corta en palabras: "v=spf1 ip4:1.2.3.4 -all" -> ["v=spf1", "ip4:1.2.3.4", "-all"]

    # Extra: mecanismo ptr (desaconsejado)
    if _usa_ptr(tokens):  # llama a la función interna de arriba. No hay return y se sigue analizando el resto
        hallazgos.append(Hallazgo(
            "advertencia",  # es advertencia porque funciona, pero no se recomienda
            "El SPF usa el mecanismo 'ptr'",  # qué se encontró
            "Es lento, poco fiable y está desaconsejado por el estándar (RFC 7208).",  # por qué importa
            "Reemplazarlo por ip4:, ip6:, a: o include:."))  # cómo arreglarlo

    # Caso 3: regla final "all" 
    reglas_all = [t for t in tokens if t in REGLAS_ALL]  # se queda solo con las palabras que sean una regla "all". Si no hay ninguna, queda []
    if reglas_all:  # lista con elementos = verdadero "si encontró alguna regla all"
        regla = reglas_all[0]  # toma la primera que encontra
        if regla in ("+all", "all"):  # "+all" y "all" a secas valen lo mismo: autorizan a cualquiera
            hallazgos.append(Hallazgo(
                "error",  # error grave
                f"El SPF termina en '{regla}': autoriza a CUALQUIER servidor a enviar correo",  # qué se encontró (muestra la regla exacta)
                "Equivale a no tener SPF: cualquiera puede suplantar el dominio y el SPF lo da por válido.",  # por qué importa
                "Cambiar el final por '-all' (rechazar) o, al menos, '~all'."))  # cómo arreglarlo
        elif regla == "?all":  # "en caso contrario, si es ?all" (neutral)
            hallazgos.append(Hallazgo(
                "advertencia",  # advertencia: no daña, pero tampoco protege
                "El SPF termina en '?all' (neutral)",  # qué se encontró
                "No toma partido sobre los remitentes no autorizados, por lo que no protege.",  # por qué importa
                "Cambiar el final por '-all' (rechazar) o '~all'."))  # cómo arreglarlo
        elif regla == "~all":  # softfail marca como sospechoso pero no rechaza
            hallazgos.append(Hallazgo(
                "ok",  # aceptable
                "El SPF termina en '~all': los remitentes no autorizados se marcan como sospechosos",  # qué se encontró
                "Es una configuración aceptable. '-all' es más estricto y rechaza directamente.",  # por qué importa
                "Opcional: pasar a '-all' cuando se confirme que todos los servidores legítimos están listados."))  # sugerencia, no obligación
        else:  # "-all": si no fue ninguna de las anteriores, solo queda esta
            hallazgos.append(Hallazgo(
                "ok",  # lo mejor
                "El SPF termina en '-all': los remitentes no autorizados son rechazados",  # qué se encontró
                "Es la configuración más estricta y la recomendada.",  # por qué importa
                "Nada que corregir."))  # no hay nada que arreglar
        return hallazgos  # ya sabemos qué decir: termina aquí

    # Caso 4: sin "all", pero con redirect= (la política está en otro dominio)
    for t in tokens:  # recorre las palabras buscando "redirect="
        if t.startswith("redirect="):  # redirect= significa "mi política es la de otro dominio"
            hallazgos.append(Hallazgo(
                "ok",  # no es un problema, es una forma válida de configurarlo
                f"El SPF delega su política en otro dominio ({t[len('redirect='):]})",  # t[9:] salta "redirect=" y deja solo el dominio: "redirect=_spf.google.com" -> "_spf.google.com"
                "Con 'redirect=' la regla final se toma del dominio indicado, así que aquí no hace falta 'all'.",  # por qué importa
                "Revisar también el SPF de ese dominio."))  # cómo seguir
            return hallazgos  # termina aquí

    # Caso 5: no termina con ninguna regla "all"
    hallazgos.append(Hallazgo(  # si llegó hasta aquí, ningún return anterior se ejecutó
        "advertencia",  # advertencia: el SPF está incompleto
        "El SPF no termina con una regla 'all'",  # qué se encontró
        "Sin regla final, los remitentes no listados quedan en un estado indefinido (neutral).",  # por qué importa
        "Agregar '-all' (o '~all') al final del registro."))  # cómo arreglarlo
    return hallazgos  # devuelve la lista con el hallazgo
