---
fase: F1a
fecha: 2026-11-26
prueba: tests/test_nginx2root_reconstruction.py
---

# nginx2root · reconstrucción (prueba de aceptación R6)

CVE-2026-123007 (HTTP/2, desbordamiento de enteros y escritura fuera de límites) y CVE-2026-123633
(HTTP/2, uso tras liberar) en NGINX. El plan pide **nivel B el mismo día**, con productos, rangos y
fix en el feed (PLAN §6 y §13).

Esto es una **reconstrucción**: snapshots hechos con datos publicados, no grabaciones de lo que
devolvían las API el 18/11. La prueba real es el siguiente caso en vivo.

## Resultado (T14)

**Pasa**, con el criterio de aceptación corregido por Juan el 2026-11-26 (PLAN §6):

- **C tras la publicación**: las dos CVE salen C a las **15:30Z**, el primer paso tras el commit
  de cvelistV5 de las 15:25:28Z.
- **B el mismo día 18/11 UTC**: CVE-2026-123007 sube a **B a las 20:10Z** (E4: nomi-sec lista el
  PoC de `sfewer-r7`, autor de la lista de confianza, en el commit de las 20:08:35Z).
- CVE-2026-123633 se queda en **C** todo el día: en su fichero de nomi-sec no hay ningún autor de
  la lista de confianza y NVD no da señal (pregunta abierta en el informe de T14).

El producto casa por la entrada de despliegue `deployment--nginx` de la lista (criterio v4): sus
pares del CNA salen de cvelistV5 con el método escrito en `deployment_leg.pairs_method` (registros
de los últimos 36 meses cuyo `product` o CPE contiene «nginx»), entre ellos `F5 / NGINX Open
Source` y `F5 / NGINX Plus`. No hay ninguna entrada hecha para el caso.

Historia: en T12 la prueba no pasaba por dos motivos. (1) La pata de despliegue no entraba en
`producto_expuesto` (resuelto en T14 con el criterio v4). (2) La B «como tarde a las 16:18Z por la
etiqueta Exploit de NVD» no se sostenía: el historial de NVD dice que a las 16:18:04Z llegó solo la
referencia de F5 y que la etiqueta «Exploit» es del **19/11 a las 21:14:10Z**, 29 horas después.
Juan corrigió el §6: NVD queda como hecho del 19/11, sin papel en la aceptación.

## Cronología comprobada (2026-11-26)

| UTC | Hecho | Fuente |
|---|---|---|
| 18/11 11:16:51 | Se crea `sfewer-r7/CVE-2026-123007` (`created_at`) | API de GitHub |
| 18/11 15:23:27 | Último push del repo (`pushed_at`); publicación de CVE-2026-123633 | API de GitHub, cvelistV5 |
| 18/11 15:23:29 | Publicación de CVE-2026-123007 | cvelistV5 |
| 18/11 15:25:24 | Entrada del `deltaLog` con las dos CVE nuevas (commit `590851bd`, 15:25:28) | cvelistV5 |
| 18/11 16:04:40 | SSVC de CISA para 123007 (`none` / `no` / `total`); en cvelistV5 a las 16:15:24 (`07059e5c`) | cvelistV5 |
| 18/11 16:18:04 | 123007 llega a NVD solo con la referencia de F5 | NVD (historial) |
| 18/11 16:38:06 | SSVC de CISA para 123633; en cvelistV5 a las 16:57:10 (`35e04952`) | cvelistV5 |
| 18/11 19:28–22:19 | Nuevas versiones de los dos registros en cvelistV5 (commits `bc1b5d8c`, `89edb96c`, `8f5b7cfd`, `6eca39f0`, `253db544`) | cvelistV5 |
| 18/11 20:08:35 | PoC-in-GitHub lista por primera vez `sfewer-r7/CVE-2026-123007` (commit `f1868572`, 7 repos) y tres repos de CVE-2026-123633, ninguno de un autor de confianza | nomi-sec |
| 18/11 20:18:54 | NVD recibe del CVE Program la referencia del blog de Rapid7, sin etiquetas | NVD (historial) |
| 18/11 23:57:33 | Catálogo KEV 2026.11.18 (`kev-data@a705bb0f`), sin ninguna de las dos | CISA KEV |
| 19/11 21:14:10 | NVD etiqueta «Exploit» las referencias de Rapid7 y Xint | NVD (historial) |
| 17/11–25/11 | Ninguna de las dos está en KEV (catálogos 2026.11.17, 2026.11.18 y 2026.11.25) | CISA KEV |
| ? | El repo pasa a público y la búsqueda lo indexa | **UNKNOWN**: se trata como no visible |

## Cómo se ejecuta

Pasos de 5 min de las 15:00Z del 18/11 a las 00:00Z del 19/11 (109 pasos). El paso de las 15:00Z
es la carga inicial de cada fuente (sin alertas, ADR-0012). Conectores reales con un transporte
simulado: cvelistV5 (cada 5 min, con el `deltaLog` y la versión de cada registro en su commit),
CISA KEV (cada 15 min; catálogo 2026.11.17 y, desde las 23:57:33Z, el 2026.11.18), PoC-in-GitHub
de nomi-sec (cada paso, con su historial de commits; sin heurísticas `poc_suspicious`, que
exigirían el código del PoC) y búsqueda de GitHub (solo con candidatos B/C; el repo nunca
aparece). NVD no tiene conector en el código: la prueba lo emula reconstruyendo su vista en cada
paso con el historial de cambios y emitiendo la señal `exploit` del contrato (`origin = reference`,
`by = nvd`). Después, el motor de reglas con las listas de `config/` y el publicador del feed,
firmado con una clave de prueba generada en el test.

## Traza

<!-- traza:inicio -->
<!-- Generado por tests/test_nginx2root_reconstruction.py. No editar a mano. -->

### Resultado con las listas de `config/` (15:00Z del 18/11 a 00:00Z del 19/11)

- CVE-2026-123007: **C** a las 15:30Z (C.exposed_product:web-proxy, C.impact:rce, C.rce_unauth).
- CVE-2026-123007: **B** a las 20:10Z (B.exposed_product:web-proxy, B.impact:rce, B.exploit:E4).
- CVE-2026-123633: **C** a las 15:30Z (C.exposed_product:web-proxy, C.impact:rce, C.rce_unauth).

Producto expuesto: 123007 → `deployment--nginx`; 123633 → `deployment--nginx`.

| Hora (UTC) | Fuentes ejecutadas | Señales nuevas | 123007 / 123633 | Por qué |
|---|---|---|---|---|
| 15:00 | cvelistv5 ok (carga inicial), cisa_kev ok (carga inicial), nomisec ok (carga inicial), nvd ok (carga inicial), github_search ok (carga inicial) | — | none / none | 123007: aún no publicada en ninguna fuente<br>123633: aún no publicada en ninguna fuente |
| 15:05–15:25 | cvelistv5 ok, nomisec ok, nvd ok, github_search ok, cisa_kev ok | — | none / none | 123007: aún no publicada en ninguna fuente<br>123633: aún no publicada en ninguna fuente |
| 15:30 | cvelistv5 ok, cisa_kev ok, nomisec ok, nvd ok, github_search ok | 123007: cvelistV5: registro del CNA f5 (CWE-191, CWE-787, CVSS:4.0)<br>123007: cvelistV5: producto F5 / NGINX Plus<br>123007: cvelistV5: producto F5 / NGINX Open Source<br>123633: cvelistV5: registro del CNA f5 (CWE-416, CVSS:4.0)<br>123633: cvelistV5: producto F5 / NGINX Open Source<br>123633: cvelistV5: producto F5 / NGINX Plus | C / C | 123007: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |
| 15:35 | cvelistv5 ok, nomisec ok, nvd ok, github_search ok | — | C / C | 123007: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |
| 15:40–16:15 | cvelistv5 ok, nomisec ok, nvd ok, github_search ok, cisa_kev ok | — | C / C | 123007: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |
| 16:20 | cvelistv5 ok, nomisec ok, nvd ok, github_search ok | 123007: cvelistV5: SSVC de CISA-ADP (exploitation none, technical_impact total) | C / C | 123007: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |
| 16:25–16:55 | cvelistv5 ok, nomisec ok, nvd ok, github_search ok, cisa_kev ok | — | C / C | 123007: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |
| 17:00 | cvelistv5 ok, cisa_kev ok, nomisec ok, nvd ok, github_search ok | 123633: cvelistV5: SSVC de CISA-ADP (exploitation none, technical_impact total) | C / C | 123007: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |
| 17:05–20:05 | cvelistv5 ok, nomisec ok, nvd ok, github_search ok, cisa_kev ok | — | C / C | 123007: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |
| 20:10 | cvelistv5 ok, nomisec ok, nvd ok, github_search ok | 123007: nomisec: repositorio sfewer-r7/CVE-2026-123007<br>123007: nomisec: repositorio LLCForge/CVE-2026-123007<br>123007: nomisec: repositorio The-DevOps-Daily/nginx2root-check<br>123007: nomisec: repositorio suominen/CVE-2026-123007<br>123007: nomisec: repositorio WormW/nginx2root-rce-lab<br>123007: nomisec: repositorio rogersouzak8s/nginx-http2-check<br>123007: nomisec: repositorio arkrwn/NGINX2Root-CVE-2026-123007<br>123633: nomisec: repositorio LLCForge/CVE-2026-123633<br>123633: nomisec: repositorio Quaerendir/cve-2026-123633-123007-nginx-audit<br>123633: nomisec: repositorio Ghost-Bx1/nginx-exploits | B / C | 123007: B.exposed_product:web-proxy + B.impact:rce + B.exploit:E4; impact_class rce; rce_sin_auth sí; exploit E4<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |
| 20:15–22:15 | cvelistv5 ok, cisa_kev ok, nomisec ok, nvd ok, github_search ok | — | B / C | 123007: B.exposed_product:web-proxy + B.impact:rce + B.exploit:E4; impact_class rce; rce_sin_auth sí; exploit E4<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |
| 22:20 | cvelistv5 ok, nomisec ok, nvd ok, github_search ok | 123633: cvelistV5: producto F5 / NGINX Plus | B / C | 123007: B.exposed_product:web-proxy + B.impact:rce + B.exploit:E4; impact_class rce; rce_sin_auth sí; exploit E4<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |
| 22:25–00:00 | cvelistv5 ok, nomisec ok, nvd ok, github_search ok, cisa_kev ok | — | B / C | 123007: B.exposed_product:web-proxy + B.impact:rce + B.exploit:E4; impact_class rce; rce_sin_auth sí; exploit E4<br>123633: C.exposed_product:web-proxy + C.impact:rce + C.rce_unauth; impact_class rce; rce_sin_auth sí; exploit ninguno |

- `VS-CVE-2026-123007` al final: nivel `B`, `impact_class` `rce`, fix 1.30.7, 1.31.9, 37.0.8.1, 37.3.0.1.
- `VS-CVE-2026-123633` al final: nivel `C`, `impact_class` `rce`, fix 1.30.7, 1.31.9, 37.0.7.1, 37.2.0.1.
- Entradas en el feed `alerts`: 10.

Búsqueda de GitHub: candidatos desde las 15:35Z (102 pasos); el repositorio no aparece porque cuándo pasó a público es UNKNOWN y se trata como no visible.
<!-- traza:fin -->

## Preguntas para Juan

Resueltas el 2026-11-26 (T14): la pata de despliegue entra en las reglas (criterio v4), el §6 y el
criterio de aceptación se corrigen y la ventana llega a las 00:00Z con nomi-sec.

1. **Conector de NVD.** El plan lo pone «bajo demanda, solo KEV y software crítico» y no hay
   conector. ¿Entra en la F1a para las referencias con etiqueta «Exploit»? En este caso llega un día
   después que nomi-sec, así que no habría adelantado la B.
2. **CVE-2026-123633 sin B el 18/11.** Solo hay PoC de autor de confianza para 123007. ¿Basta con
   que una de las dos CVE del caso salga B, o se espera B en las dos?
3. **Rangos de CVE-2026-123633 en el feed.** El CNA declara `1.19.7, lessThan *` con
   `versionType: custom` y los otros dos tramos con `semver`. El conversor de CVE 5 los separa en un
   rango `ECOSYSTEM` con solo `introduced: 1.19.7` y otro `SEMVER` con los fix. Un cliente que solo
   lea OSV verá 1.30.7 y 1.31.9 como afectadas por el rango `ECOSYSTEM` abierto. En 123007 los tres
   tramos son `semver`, van en un solo rango y la evaluación ordenada de OSV da lo correcto. ¿Se
   unifica el tipo cuando un `affected` mezcla `semver` y `custom`, o se deja el tramo `custom` en
   `raw_ranges`? Es un cambio del conversor (T5), fuera de esta prueba.
