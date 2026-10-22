# Fase 1: diagnóstico manual

Objetivo: consultar a mano los registros SPF, DKIM y DMARC de nuestro dominio y de otros dominios conocidos, y documentar qué encontramos. Estos resultados se usan después para comprobar que la herramienta da lo mismo que la consulta manual.

## Comandos usados

```bash
dig +short TXT dominio.com                      # SPF (buscar la línea v=spf1)
dig +short TXT _dmarc.dominio.com               # DMARC
dig +short TXT selector._domainkey.dominio.com  # DKIM (probar google, selector1, s1, default...)
```

Windows sin `dig`: `nslookup -type=TXT dominio.com`

## Dominio propio: ____________

| Registro | Valor encontrado | ¿Qué problemas vemos? |
|---|---|---|
| SPF | | |
| DMARC | | |
| DKIM (selector: ___) | | |

## Dominios de referencia (solo lectura)

| Dominio | SPF termina en | DMARC p= | DKIM (selector) | Comentario |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |

## Comparación con la herramienta

| Dominio | ¿Coincide con la consulta manual? | Observaciones |
|---|---|---|
| | | |

## Qué aprendimos

-
