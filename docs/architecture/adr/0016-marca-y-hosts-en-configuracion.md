---
adr: "0016"
titulo: Hosts, nombre y marca en configuración
estado: aceptado
fecha: 2026-11-25
afecta: [CMP-001, CMP-002, CMP-005, CMP-011]
sustituye: null
---

## Contexto

Al principio el producto vive en `vuln.` y `api.vuln.` de la zona actual (P-3). Si funciona, el
objetivo de negocio es migrarlo a una marca propia, con dominio propio, y monetizarlo. Esa
migración no debe exigir tocar código.

## Decisión

Nada de lo que depende de la marca se escribe en el código:
- hosts públicos (front, API, feed);
- nombre del producto y textos de marca;
- emisor del feed y `kid` de la clave;
- URL base de las alertas y de `/.well-known/`;
- plantillas de posts.

Todo sale de configuración:
- `config/brand.example.yaml` en el repo, con valores ficticios;
- los valores reales, en variables del pipeline (regla 8);
- en el front, como variables de build de Vite (`VITE_*`) inyectadas en el despliegue.

Los identificadores del contrato **no** dependen de la marca: los IDs de alerta (`VS-CVE-…`) y el
prefijo `vuln_sentinel` de la extensión OSV son estables y no cambian si cambia el nombre comercial.

## Alternativas descartadas

- Hosts escritos en el código y en los tests: la migración sería un cambio de código y un riesgo de
  romper el contrato.

## Consecuencias

- Migrar consiste en: DNS y Tunnel nuevos, variables nuevas, redirección 301 de los hosts antiguos
  durante el periodo de convivencia y aviso en el feed (`/.well-known/` publica los dos emisores).
- Un test falla si aparece un host de la zona real en el código o en los fixtures.

## Evidencia

Decisión de Juan (P-3), 2026-11-25.
