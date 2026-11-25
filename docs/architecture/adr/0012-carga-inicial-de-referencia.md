---
adr: "0012"
titulo: Carga inicial de referencia por fuente
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-003, CTL-007, THR-007]
sustituye: null
---

## Contexto

En el primer arranque, todo el histórico de KEV, Exploit-DB, Metasploit y nomi-sec es «nuevo» y
cumpliría A o B miles de veces (revisión R2).

## Decisión

La primera ejecución completa de cada fuente es su referencia: se guarda con `baseline = true` y no
genera alertas. Una CVE se evalúa para alertar si se publicó en los últimos N = 14 días, o si
recibe una señal nueva posterior a la referencia de su fuente.

## Alternativas descartadas

- Alertar solo CVE de los últimos N días: perdería la CVE antigua que entra hoy en KEV.

## Consecuencias

Una fuente añadida después tampoco provoca una avalancha. N se revisa con datos tras la F1b.

## Evidencia

Pruebas «carga inicial → 0 alertas» y «fuente nueva → 0 alertas».
