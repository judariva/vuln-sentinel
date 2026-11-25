# Estado · vuln-sentinel

Actualizado: 2026-11-25.

## Fase actual: F0 cerrada en local; decisiones P-1…P-15 aplicadas al plan

| Elemento | Estado |
|---|---|
| F0 (reglas, estructura, CI, ADR, métricas) | Commit inicial local |
| Decisiones P-1…P-15 | Cerradas por Juan y aplicadas en `PLAN.md` (commit aparte) |
| ADR | 0001–0020. Aceptados: 0004, 0005, 0006, 0009 (condicionado a G-6), 0015, 0016, 0019, 0020. Propuestos: 0017 (redes) y 0018 (licencias). 0011, sustituido por 0018 |
| Cambio de diseño | Feed completo + feed de alertas (ADR-0019). Las listas solo deciden la urgencia |
| VulnCheck KEV | **Fuera de la v1** por sus términos (ADR-0020) |
| Test de hosts reales (ADR-0016) | Hecho; en CI lee `VS_FORBIDDEN_HOSTS` de un secret |
| Push | No. Espera al repo (G-13) y a las licencias por directorio (ADR-0018) |

## Pendiente de Juan (PLAN.md, «Pendiente de Juan»)

- J-1: aceptar ADR-0018 (FSL-1.1-ALv2 para el motor).
- J-2: aceptar ADR-0017 tras comprobar los términos de Buffer y las credenciales de X.
- J-3: VulnCheck, con permiso por escrito o licencia (si se quiere).
- J-4: fecha del cambio de facturación (solo en `local/`).
- J-5: crear el repo (G-13).

## Búsqueda de fugas (2026-11-25, segundo commit; 54 ficheros que entran en git, sin `uv.lock` ni `LICENSE`)

```
## credencial: 4   ← las reglas .env del .gitignore y su cita en este mismo fichero; no son fugas
## oferta: 0       (la primera pasada encontró 2 términos de la lista de fugas en el plan; corregido)
## gateway: 0
## plataforma: 0
## uuid: 0
## ip: 0
## correo: 0
## recursos: 0     (falso positivo «mariadb.com» descartado afinando el patrón)
```

## Siguiente

1. **Antes del primer push** (ADR-0018, cuando Juan lo acepte): licencias por directorio,
   cabeceras SPDX, `CONTRIBUTING` con CLA y DCO.
2. **F1a-0**: scripts de las dos listas y PR de revisión de Juan (necesita el repo).
3. **F1a**: modelo de datos, `config/sources.yaml` con uso comercial, reglas, colectores (cvelistV5,
   CISA KEV, nomi-sec, búsqueda de GitHub, nginx.org), feed completo y de alertas, firma, API y
   reconstrucción de nginx2root.
