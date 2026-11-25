# Estado · vuln-sentinel

Actualizado: 2026-11-25.

## Fase actual: F0 cerrada; plan con las decisiones de Juan; repo privado en GitHub

| Elemento | Estado |
|---|---|
| Licencia | **Todo Apache-2.0** (ADR-0011). ADR-0018 (open core) rechazado. Contribuciones con DCO (`CONTRIBUTING.md`) |
| Sostenibilidad | Donaciones, no venta. Donaciones en Bitcoin sin custodia: ADR-0021 (propuesto), fase F4b con el interruptor `donations.enabled` |
| Transparencia | Pantalla pública «Coste del proyecto»: coste real frente a lo recibido (§9, §10). Tablas `cost_daily` y `donation_received`, sin datos del donante; test que lo comprueba |
| Redes | ADR-0017 propuesto: Buffer comprobado; aceptable con confirmación por escrito de su cláusula 4.2(n) |
| VulnCheck KEV | Fuera de la v1 por sus términos (ADR-0020) |
| ADR | 0001–0021. Propuestos: 0017 y 0021. Rechazado: 0018 |
| Repo | Privado en GitHub, `main` protegida (PR y CI). Hacerlo público lo decide Juan, con otra búsqueda de fugas sobre el historial |

## Pendiente de Juan

- J-2: aceptar o no ADR-0017 (Buffer, condicionado a su confirmación por escrito).
- J-3: VulnCheck, solo con permiso por escrito o licencia.
- J-6: aceptar o no ADR-0021 (donaciones).
- J-7: hacer público el repo, cuando lo decida.

## Siguiente: F1a-0 y F1a (sesión nueva)

1. **F1a-0**: scripts que generan `exposed-products` y `trusted-exploit-authors` con su criterio, y
   PR de revisión de Juan. Fusionado antes de cualquier fixture de nginx2root.
2. **F1a**: modelo de datos, `config/sources.yaml` con uso comercial y aislamiento, reglas,
   colectores (cvelistV5, CISA KEV, nomi-sec, búsqueda de GitHub, nginx.org), feed completo y de
   alertas, firma, API y reconstrucción de nginx2root.

La búsqueda de fugas de cada push se registra en `local/` (informe de la sesión), no aquí.
