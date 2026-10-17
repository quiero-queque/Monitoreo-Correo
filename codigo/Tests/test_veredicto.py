from modelos import Hallazgo
from veredicto import veredicto

def h(sev):
    return Hallazgo(sev, "m", "p", "s")

def test_con_errores():
    assert veredicto([h("ok"), h("error")]) == "con errores"

def test_con_advertencias():
    assert veredicto([h("ok"), h("advertencia")]) == "con advertencias"

def test_aprobado():
    assert veredicto([h("ok")]) == "aprobado"
