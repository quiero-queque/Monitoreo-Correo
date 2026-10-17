import sys
from dns_utils import obtener_txt, obtener_spf, obtener_dmarc
from analisis_spf import analizar_spf
from analisis_dmarc import analizar_dmarc
from analisis_dkim import analizar_dkim
from veredicto import veredicto

SELECTORES = ["default", "google", "selector1", "selector2", "s1", "k1"]
ICONOS = {"ok": "✅", "advertencia": "⚠️ ", "error": "❌"}

def mostrar(titulo, hallazgos):
    print(f"\n== {titulo} ==")
    for h in hallazgos:
        print(f"{ICONOS[h.severidad]} {h.mensaje}")
        if h.severidad != "ok":
            print(f"     Por qué importa: {h.por_que}")
            print(f"     Cómo arreglarlo: {h.solucion}")

def auditar(dominio, selector=None):
    # TODO 1: hallazgos_spf   = analizar_spf(obtener_spf(dominio))
    # TODO 2: hallazgos_dmarc = analizar_dmarc(obtener_dmarc(dominio))
    # TODO 3: DKIM. Si dieron `selector`, probar solo ese. Si no, recorrer
    #         SELECTORES y quedarse con el primero que tenga registros:
    #         registros = obtener_txt(f"{sel}._domainkey.{dominio}")
    #         Luego: hallazgos_dkim = analizar_dkim(registros, sel)
    # TODO 4: mostrar("SPF", ...), mostrar("DMARC", ...), mostrar("DKIM", ...)
    # TODO 5: juntar los tres en una lista (hallazgos_spf + hallazgos_dmarc + ...)
    #         y mostrar el veredicto final con veredicto(...)
    ...

if __name__ == "__main__":
    dominio = sys.argv[1]
    selector = sys.argv[2] if len(sys.argv) > 2 else None
    auditar(dominio, selector)
