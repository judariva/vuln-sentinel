---
adr: "0013"
titulo: B exige impacto mínimo
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-003, CMP-004, THR-002]
sustituye: null
---

## Contexto

Un exploit de DoS o de fuga de versión en un producto expuesto no es urgente (revisión R3).

## Decisión

B exige que `impact_class` sea `rce`, `auth_bypass` o `arbitrary_rw`, calculada de forma
determinista a partir de CWE y CVSS, y que el exploit corresponda a ese impacto. Los módulos
`auxiliary/dos` y las entradas `dos` de Exploit-DB no cuentan. El agente no puede declarar más
impacto que el del CVE.

## Alternativas descartadas

- Cualquier exploit en un producto expuesto: ruido.

## Consecuencias

Hay riesgo de falso negativo si el CNA clasifica mal la CWE. Se mide con la métrica de fallos
(altas de KEV sin B o A previa).

## Evidencia

Caso de evaluación «DoS con exploit en nginx → no B».
