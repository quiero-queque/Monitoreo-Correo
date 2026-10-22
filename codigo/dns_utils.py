import dns.resolver

# Define una función que recibe un nombre DNS
def obtener_txt(nombre):
   
    """devuelve la lista de textos TXT de un nombre DNS ([] si no existe o no tiene TXT).""" #descripcion
    
    try: # Intenta, si algo falla adentro, Python salta al except en vez de caerse.
        respuesta = dns.resolver.resolve(nombre, "TXT") # pregunta al DNS por los registros de tipo TXT de ese nombre y guarda la respuesta.
    
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer): # Se ejecuta si el nombre no existe (NXDOMAIN) o existe pero no tiene TXT (NoAnswer).
        return []  # Devuelve una lista vacía, si no hay registro es un dato, no un error.

    return [b"".join(r.strings).decode() for r in respuesta]     # Recorre cada registro (r) de la respuesta, une sus trozos de 255 bytes con b"".join y lo convierte de bytes a texto con decode(). resulta en una lista de textos

def obtener_spf(dominio): # función que recibe un dominio
    """Devuelve solo los TXT del dominio que son un registro SPF (empiezan con v=spf1).""" #descripcion
    resultado = []  # Lista vacía donde se ira guardando
    for texto in obtener_txt(dominio):  # Pide todos los TXT del dominio y los recorre uno por uno.
        if texto.strip().lower().startswith("v=spf1"): # strip() quita espacios de los bordes, lower() pasa a minúsculas y startswith(), pregunta si el texto empieza con "v=spf1". Así se reconoce un SPF entre los demás TXT.
            resultado.append(texto)  # Si es un SPF, lo agrega a la lista de resultados.
    return resultado # Devuelve solo los SPF, uno, varios o ninguno

def obtener_dmarc(dominio): 
    """Devuelve los TXT de _dmarc.<dominio> que son un registro DMARC (empiezan con v=DMARC1).""" #descripcion
    resultado = [] # lista donde guardariamos los registros DMARC
    # DMARC vive en un nombre especial "_dmarc." pegado delante del dominio.
    for texto in obtener_txt("_dmarc." + dominio):  # Para usm.cl consulta "_dmarc.usm.cl". Recorre los TXT que vengan.
        if texto.strip().lower().startswith("v=dmarc1"): # pasa a minúsculas (por eso se compara con "v=dmarc1") y pregunta si empieza así, funciona sin importar como se ponga el dominio
            resultado.append(texto) # Si es un DMARC, lo guarda en la lista.
    return resultado    # Devuelve los DMARC encontrados: [] si no hay, uno (lo normal) o varios (error)

def parsear_etiquetas(texto): #función que recibe un texto como "v=DMARC1; p=reject; pct=100;"
    """Convierte 'v=DMARC1; p=reject; pct=100;' en {'v': 'DMARC1', 'p': 'reject', 'pct': '100'}."""  # explica conversión de texto a diccionario.
    resultado = {}     # Diccionario vacío
    for trozo in texto.split(";"):   # split(";") corta el texto en cada ";". Queda ["v=DMARC1", ""], El último trozo es vacío porque el texto termina en ";". Recorre cada trozo
        trozo = trozo.strip()   #Quita los espacios sobrantes de los bordes: " p=reject" pasa a "p=reject"
        if "=" not in trozo:  # si el trozo no tiene "=", no es una pareja clave=valor (como el trozo vacío del final) trozo vacío (el texto termina en ';') o sin formato clave=valor
            continue # continue = "salta a la siguiente vuelta del for" sin ejecutar lo que sigue
        # Corta en el PRIMER "=" y reparte: "p=reject" -> clave = "p", valor = "reject"
        # El 1 importa las claves DKIM terminan en "=" y no hay que cortarlas ahi
        clave, valor = trozo.split("=", 1)   # solo en el PRIMER '=' (las claves DKIM terminan con '=')
        resultado[clave.strip().lower()] = valor.strip()     # guarda la pareja en el diccionario, con la clave en minúsculas y sin espacios
    return resultado   # devuelve el diccionario completo: {"v": "DMARC1", "p": "reject", "pct": "100"}
