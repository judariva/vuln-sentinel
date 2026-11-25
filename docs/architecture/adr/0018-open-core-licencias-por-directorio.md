---
adr: "0018"
titulo: Open core con licencias por directorio (Apache-2.0 + FSL-1.1-ALv2)
estado: rechazado
fecha: 2026-11-25
afecta: []
sustituye: null
---

> **Rechazado por Juan el 2026-11-25.** El modelo de sostenibilidad es de **donaciones, no de
> venta**: el feed es siempre gratis e igual para todos. Ese modelo pide un proyecto 100 % abierto,
> así que todo el repositorio queda con Apache-2.0 y vuelve a valer ADR-0011. El análisis de abajo
> se conserva como histórico de la decisión.

## Contexto

P-11: open core. El contrato del feed, el JSON Schema, el verificador de firma y los consumidores de
ejemplo van con Apache-2.0. El motor (reglas, colectores, agente, API y portal) va con una licencia
source-available que no permita ofrecerlo como servicio y que pase a abierta con los años. Hay que
comparar FSL y BSL. El objetivo de negocio es monetizar si el producto funciona (P-3).

## Decisión

- **Apache-2.0**: `schema/`, `examples/` (verificador y consumidores), `docs/` y `config/*.example.yaml`.
- **FSL-1.1-ALv2** (SPDX `FSL-1.1-ALv2`): `src/` (núcleo, reglas, colectores, agente, API), `web/`
  (portal) e `infra/`. Cada versión pasa a Apache-2.0 a los **2 años**.
- `LICENSE` por directorio. El `LICENSE` de la raíz es Apache-2.0 con una cláusula que remite a
  `src/LICENSE`, `web/LICENSE` e `infra/LICENSE` (patrón de PostHog). Cada fichero lleva su cabecera
  `SPDX-License-Identifier`, y `NOTICE` recoge las atribuciones de datos.
- Contribuciones: **CLA** para el motor (sin él no se puede ofrecer licencia comercial ni volver a
  licenciar) y **DCO** para la parte Apache.
- **Antes del primer push** (G-13): dividir `LICENSE` y `NOTICE`, añadir las cabeceras SPDX y
  cambiar `license` en `pyproject.toml`. Un test comprueba que cada fichero de `src/` y `web/` lleva
  la cabecera FSL.

## Comparativa (2026-11-25)

| | FSL-1.1-ALv2 | BUSL-1.1 |
|---|---|---|
| Prohibido | «Competing Use»: ofrecerlo en un producto o servicio comercial que lo sustituya o dé funcionalidad sustancialmente similar ([fsl.software](https://fsl.software/)) | Lo que no cubra el *Additional Use Grant*, que redacta el licenciante ([mariadb.com/bsl11](https://mariadb.com/bsl11/)) |
| Paso a abierta | Fijo: 2 años, a Apache-2.0 | *Change Date* (máx. 4 años) a GPLv2+ o compatible |
| Configurable | No: plantilla cerrada | Sí: Grant, fecha y licencia final |
| SPDX / OSI | `FSL-1.1-ALv2` / no OSI | `BUSL-1.1` / no OSI ([spdx.org](https://spdx.org/licenses/)) |
| Quién la usa | Sentry, Codecov ([open.sentry.io](https://open.sentry.io/licensing)) | Terraform ([LICENSE](https://github.com/hashicorp/terraform/blob/main/LICENSE)) |

**Se elige FSL** porque:
- termina en Apache-2.0, la misma licencia que el resto del repo;
- no hay que redactar un Grant (menos ambigüedad);
- cubre justo el caso de un servicio competidor.

BUSL solo compensaría si se quisieran 3-4 años de protección o un Grant a medida.

## Alternativas descartadas

- ELv2 y PolyForm Shield: nunca pasan a abiertas.
- Todo Apache-2.0 (ADR-0011): no protege la monetización.
- Repos separados para contrato y motor: GitHub mostraría Apache-2.0 en el del contrato, pero se
  duplica la gestión. Se puede revisar más adelante.

## Consecuencias

- GitHub mostrará la licencia del repo como «Other», porque solo lee el `LICENSE` de la raíz y la
  excepción va dentro de él. El README lo explica.
- Las dependencias Apache dentro del motor conservan su licencia y su NOTICE.
- **Revisión legal de Juan antes de monetizar**: queda fuera del alcance de este repo.

## Evidencia

https://fsl.software/FSL-1.1-ALv2.template.md, https://github.com/PostHog/posthog/blob/master/LICENSE,
https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository
(consultadas el 2026-11-25).
