from dataclasses import dataclass

@dataclass
class Hallazgo:
    severidad: str   # "ok", "advertencia" o "error"
    mensaje: str     # qué se encontró
    por_que: str     # por qué importa
    solucion: str    # cómo arreglarlo
