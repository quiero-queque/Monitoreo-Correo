# Email Auth Auditor

Herramienta en Python que audita la autenticación de correo (**SPF, DKIM y DMARC**) de un dominio y entrega un "chequeo de salud" entendible para personas no técnicas.

> Proyecto académico (Desafío 1). Solo consulta información pública vía DNS.

## ¿Qué problema resuelve?

En SMTP cualquiera puede escribir cualquier remitente, lo que permite suplantar dominios (phishing). SPF, DKIM y DMARC lo evitan publicando información en DNS. Desde 2024 Google, Yahoo y Microsoft los exigen para correo masivo: sin ellos, los correos son rechazados.

| Mecanismo | Pregunta que responde | Se publica en |
|---|---|---|
| **SPF** | ¿Esta IP está autorizada a enviar por el dominio? | TXT de `dominio.com` |
| **DKIM** | ¿El mensaje está firmado y no fue alterado? | TXT de `selector._domainkey.dominio.com` |
| **DMARC** | ¿Coincide con el "De:" y qué hago si falla (`none` / `quarantine` / `reject`)? | TXT de `_dmarc.dominio.com` |

## Qué hace la herramienta

Dado un dominio, consulta los tres registros, valida su sintaxis y reglas (un solo SPF, máximo 10 lookups, no terminar en `+all`, política DMARC, `p=` en DKIM) y devuelve:

- ✅ **Aprobado**
- ⚠️ **Con advertencias**
- ❌ **Con errores**

Cada resultado incluye una explicación en lenguaje claro.

## Instalación y uso

```bash
git clone https://github.com/<usuario>/email-auth-auditor.git
cd email-auth-auditor
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m auditor.cli ejemplo.com --selector google
pytest
```

> Sección de uso por completar a medida que avance la CLI.

## Estructura

```
auditor/   dns_utils.py, spf.py, dkim.py, dmarc.py, scoring.py, report.py, cli.py
tests/
docs/      fase1.md, informe.md
docker/    (Fase 4, opcional)
```

Cada módulo devuelve `{"status": "ok|warning|error", "findings": [...], "explanation": "..."}`.

## Trabajo en equipo

- `main` solo se modifica por Pull Request revisado por otra persona.
- Una rama por módulo (`feat/spf`, `feat/dmarc`, `feat/dkim`).

| Integrante | Rol |
|---|---|
| _Samuel Cament_ | SPF + utilidades DNS |
| _Cristobal Oyarzun_ | DMARC + reporte |
| _Benjamin Vargas_ | DKIM + scoring + CLI |

README e informe se reparten entre los tres.

## Roadmap

- [ ] Fase 1: diagnóstico manual (`docs/fase1.md`)
- [ ] Fase 2: módulos SPF, DKIM, DMARC + CLI
- [ ] Fase 3: reporte HTML o terminal
- [ ] Fase 4 (opcional): simulación local con Docker/Mailpit
- [ ] Informe y demo

## Referencias

RFC 7208 (SPF), RFC 6376 (DKIM), RFC 9989–9991 (DMARCbis), [dnspython](https://dnspython.readthedocs.io/), [MXToolbox](https://mxtoolbox.com/), [Mailpit](https://mailpit.axllent.org/)
