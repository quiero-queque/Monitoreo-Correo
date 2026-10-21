from dns_utils import obtener_spf, obtener_dmarc, parsear_etiquetas
from analisis_spf import analizar_spf

# Define el dominio que se utilizará para realizar las consultas y el análisis
dominio = "gmail.com"

# Consulta el registro SPF del dominio e imprime el resultado obtenido
print("SPF:  ", obtener_spf(dominio))

# Consulta el registro DMARC del dominio e imprime el resultado obtenido
print("DMARC:", obtener_dmarc(dominio))

# Prueba la función parsear_etiquetas con un registro DMARC de ejemplo
# La función debería separar sus componentes, como v, p y pct.
print("Parser:", parsear_etiquetas("v=DMARC1; p=reject; pct=100;")) # muestra un titulo para indicar que comenzará el análisis del registro SPF
