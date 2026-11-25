# Estado · vuln-sentinel

Actualizado: 2026-11-25.

## Fase actual: F0 cerrada en local → siguiente, F1a

| Elemento | Estado |
|---|---|
| Reglas en `CLAUDE.md` (paso 0) | Hecho. Las decisiones originales y la revisión son histórico privado en `local/` |
| Revisión del plan (R1–R10 y correcciones menores) | Aplicada en `PLAN.md`. Resumen público en `docs/journey/00-origen-y-decisiones.md` |
| P-13 (continuidad de la suscripción) | Resuelta: ADR-0015, G-14 |
| P-15 (ficheros privados fuera del repo) | Resuelta |
| P-1 … P-12 | Pendientes de Juan; no bloquean F1a |
| Estructura, `pyproject.toml`, CI, licencia, `NOTICE` | Hecho |
| ADR 0001–0015 + plantilla | 0015 aceptado; el resto propuestos |
| `architecture.yaml` + test de IDs | Hecho |
| DDL en borrador + consultas de métricas + test de parseo | Hecho |
| Criterio de `trusted-exploit-authors` y de `exposed-products` | Escrito; listas vacías hasta F1a |
| Commit inicial de F0 | Local. **Sin push**: espera a que Juan cree el repo (G-13) |

## Búsqueda de fugas (2026-11-25, sobre los 47 ficheros que entran en git, sin `uv.lock` ni `LICENSE`)

```
ficheros_revisados=47
## credencial: 2
.gitignore:3:.env          ← regla de ignorar, no es una fuga
.gitignore:4:.env.*        ← ídem
## oferta: 0
## gateway: 0
## plataforma: 0
## uuid: 0
## ip: 0
## correo: 0
## recursos: 0
```

Patrones: carpeta y variables de la credencial, tipo de oferta, AI Gateway sin autenticación,
nombre de la plataforma, UUID, IP, correos y nombres de recursos internos. La primera pasada
encontró el nombre propuesto para el RG en G-1; se sustituyó por «nombre en variables del
pipeline».

## Bloqueos

- **Push**: el repo lo crea Juan (G-13).
- **F1b (despliegue)**: gate de plataforma G-1…G-14.
- **F2 (IA)**: G-6, P-1 y P-2.

## Siguiente: F1a (sesión nueva)

1. Modelo de datos y migraciones (Alembic) a partir de `docs/metrics/schema-draft.sql`.
2. Script que genera `trusted-exploit-authors.yaml` con el criterio escrito. **Commit antes de
   cualquier fixture de nginx2root** (R7).
3. Reglas A/B/C con `impact_class` y carga inicial; tests de carga inicial = 0, DoS ≠ B, ruido,
   fallo de fuente y monotonía.
4. Colectores de cvelistV5, KEV (CISA y VulnCheck), nomi-sec, búsqueda de GitHub y nginx.org.
5. Feed OSV firmado y API.
6. Reconstrucción de nginx2root: B como tarde a las 16:18Z.
7. Las consultas de métricas, en CI contra una base de datos real.
