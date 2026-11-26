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

## Resultado

**No pasa.** Con las listas de `config/` (v3), ninguna de las dos CVE sube de `none` entre las
15:00Z y las 18:00Z. El feed completo las publica con sus rangos y fix, y la firma verifica, pero
el feed de alertas queda vacío. Las dos pruebas de aceptación están marcadas `xfail` estricto con el
motivo.

Fallan dos cosas distintas:

1. **`producto_expuesto` no casa (falta C y B).** El CNA (`f5`) firma los productos como
   `F5 / NGINX Open Source` y `F5 / NGINX Plus`. En `config/exposed-products.yaml`, nginx solo
   aparece en `deployment_leg.products` (`id: deployment--nginx`, `name: nginx`, rango 2), sin
   `vendor`, `product`, alias ni CPE. Las reglas (`vs.rules.lists.parse_lists`) solo cargan la
   sección `products`, así que esa entrada no decide nada. El impacto sí casa: `impact_class = rce`
   (CWE-191/787 y CWE-416 con VC:H/VI:H, y SSVC `technical_impact = total`) y `AV:N/PR:N/UI:N`.
   Paso exacto: en cada evaluación del motor, `producto_expuesto(refs, lists)` devuelve `None`.
2. **La señal de NVD de las 16:18Z no existía (falta B).** El historial de cambios de NVD dice que a
   las 16:18:04Z llegó solo la referencia de F5 (`K000163926`, sin etiquetas). La referencia del
   blog de Rapid7 llega a las 20:18:54Z, la añade el contenedor del CVE Program y sin etiquetas. La
   etiqueta «Exploit» (en Rapid7 y en Xint) la pone NVD en su análisis inicial del **19/11 a las
   21:14:10Z**. La cronología del §6 («18/11 16:18, llega a NVD con la etiqueta Exploit en la
   referencia de Rapid7») junta dos hechos que pasaron con 29 horas de diferencia.

El contrafactual de la traza (las mismas fuentes con un producto que case los pares del CNA) da C a
las 15:30Z para las dos y ninguna B en la ventana: aunque se arregle la lista, la B «como tarde a
las 16:18Z» no sale con los datos publicados.

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
| 18/11 20:08:35 | PoC-in-GitHub lista por primera vez `sfewer-r7/CVE-2026-123007` (commit `f1868572`) | nomi-sec |
| 18/11 20:18:54 | NVD recibe del CVE Program la referencia del blog de Rapid7, sin etiquetas | NVD (historial) |
| 19/11 21:14:10 | NVD etiqueta «Exploit» las referencias de Rapid7 y Xint | NVD (historial) |
| 17/11–25/11 | Ninguna de las dos está en KEV (catálogos 2026.11.17 y 2026.11.25) | CISA KEV |
| ? | El repo pasa a público y la búsqueda lo indexa | **UNKNOWN**: se trata como no visible |

Fuera de la ventana de la prueba, con una lista que casara: nomi-sec a las 20:08Z daría E4 por
cuenta de confianza (`sfewer-r7` está en `trusted-exploit-authors.yaml` por sus módulos de
Metasploit), es decir, B hacia las 20:10Z del 18/11. Esto no se simula aquí: es una lectura de los
datos.

## Cómo se ejecuta

Pasos de 5 min de las 15:00Z a las 18:00Z. El paso de las 15:00Z es la carga inicial de cada fuente
(sin alertas, ADR-0012). Conectores reales con un transporte simulado: cvelistV5 (cada 5 min, con
el `deltaLog` y la versión de cada registro en su commit), CISA KEV (cada 15 min, catálogo
2026.11.17) y búsqueda de GitHub (solo con candidatos B/C; el repo nunca aparece). NVD no tiene
conector en el código: la prueba lo emula reconstruyendo su vista en cada paso con el historial de
cambios y emitiendo la señal `exploit` del contrato (`origin = reference`, `by = nvd`). Después, el
motor de reglas con las listas de `config/` y el publicador del feed, firmado con una clave de
prueba generada en el test.

## Traza

<!-- traza:inicio -->
<!-- Generado por tests/test_nginx2root_reconstruction.py. No editar a mano. -->

### Resultado con las listas de `config/`

- CVE-2026-123007: ningún cambio de nivel entre las 15:00Z y las 18:00Z.
- CVE-2026-123633: ningún cambio de nivel entre las 15:00Z y las 18:00Z.

| Hora (UTC) | Fuentes ejecutadas | Señales nuevas | 123007 / 123633 | Por qué |
|---|---|---|---|---|
| 15:00 | cvelistv5 ok (carga inicial), cisa_kev ok (carga inicial), nvd ok (carga inicial), github_search ok (carga inicial) | — | none / none | 123007: aún no publicada en ninguna fuente<br>123633: aún no publicada en ninguna fuente |
| 15:05–15:25 | cvelistv5 ok, nvd ok, github_search ok, cisa_kev ok | — | none / none | 123007: aún no publicada en ninguna fuente<br>123633: aún no publicada en ninguna fuente |
| 15:30 | cvelistv5 ok, cisa_kev ok, nvd ok, github_search ok | 123007: cvelistV5: registro del CNA f5 (CWE-191, CWE-787, CVSS:4.0)<br>123007: cvelistV5: producto F5 / NGINX Plus<br>123007: cvelistV5: producto F5 / NGINX Open Source<br>123633: cvelistV5: registro del CNA f5 (CWE-416, CVSS:4.0)<br>123633: cvelistV5: producto F5 / NGINX Open Source<br>123633: cvelistV5: producto F5 / NGINX Plus | none / none | 123007: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno |
| 15:35–16:15 | cvelistv5 ok, nvd ok, github_search ok, cisa_kev ok | — | none / none | 123007: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno |
| 16:20 | cvelistv5 ok, nvd ok, github_search ok | 123007: cvelistV5: SSVC de CISA-ADP (exploitation none, technical_impact total) | none / none | 123007: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno |
| 16:25–16:55 | cvelistv5 ok, nvd ok, github_search ok, cisa_kev ok | — | none / none | 123007: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno |
| 17:00 | cvelistv5 ok, cisa_kev ok, nvd ok, github_search ok | 123633: cvelistV5: SSVC de CISA-ADP (exploitation none, technical_impact total) | none / none | 123007: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno |
| 17:05–18:00 | cvelistv5 ok, nvd ok, github_search ok, cisa_kev ok | — | none / none | 123007: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno<br>123633: producto_expuesto: no casa (F5 / NGINX Open Source; F5 / NGINX Plus); impact_class rce; rce_sin_auth sí; exploit ninguno |

Registro del feed `VS-CVE-2026-123007` al final: nivel `none`, `impact_class` `rce`, fix 1.30.7, 1.31.9, 37.0.8.1, 37.3.0.1; en el feed `alerts`: 0 entradas.

### Contrafactual de diagnóstico (no es el resultado)

Las mismas fuentes con las listas de `config/` más un producto con los pares del CNA
(`F5 / NGINX Open Source`, alias `F5 / NGINX Plus`). No cambia ninguna lista del repo.

- CVE-2026-123007: **C** a las 15:30Z (C.exposed_product:web-proxy, C.impact:rce, C.rce_unauth).
- CVE-2026-123633: **C** a las 15:30Z (C.exposed_product:web-proxy, C.impact:rce, C.rce_unauth).

Búsqueda de GitHub: candidatos desde las 15:35Z (30 pasos); el repositorio no aparece porque cuándo pasó a público es UNKNOWN y se trata como no visible.
<!-- traza:fin -->

## Preguntas para Juan

1. **Lista de productos expuestos.** ¿Cómo entra la pata de despliegue en las reglas? Hoy
   `deployment_leg` no la lee `parse_lists` y sus entradas no tienen `vendor`/`product`/CPE. ¿Se
   amplía el generador para dar a esas entradas los pares del CNA y los CPE (para nginx:
   `F5 / NGINX Open Source`, `F5 / NGINX Plus`; CPE de NVD `cpe:2.3:a:f5:nginx_plus`,
   `cpe:2.3:a:f5:nginx_open_source`, a comprobar) y que las reglas las carguen? Es un cambio del
   criterio v3 y va por PR revisado (R7).
2. **Cronología del §6.** La B «como tarde a las 16:18Z por la etiqueta Exploit de NVD» no se
   sostiene: la etiqueta es del 19/11 21:14Z. ¿Se corrige el §6 y el criterio de aceptación? Con
   los datos publicados, la primera señal observable de exploit el 18/11 es nomi-sec a las 20:08Z
   (E4 por autor de confianza), que sigue siendo «B el mismo día» si la lista casa.
3. **Conector de NVD.** El plan lo pone «bajo demanda, solo KEV y software crítico» y no hay
   conector. ¿Entra en la F1a para las referencias con etiqueta «Exploit»? En este caso llega un día
   después que nomi-sec, así que no habría adelantado la B.
4. **Ventana de la prueba.** ¿Se amplía la reconstrucción hasta el final del 18/11 (con nomi-sec)
   cuando se resuelva la pregunta 1, para comprobar la B de las 20:10Z?
5. **Rangos de CVE-2026-123633 en el feed.** El CNA declara `1.19.7, lessThan *` con
   `versionType: custom` y los otros dos tramos con `semver`. El conversor de CVE 5 los separa en un
   rango `ECOSYSTEM` con solo `introduced: 1.19.7` y otro `SEMVER` con los fix. Un cliente que solo
   lea OSV verá 1.30.7 y 1.31.9 como afectadas por el rango `ECOSYSTEM` abierto. En 123007 los tres
   tramos son `semver`, van en un solo rango y la evaluación ordenada de OSV da lo correcto. ¿Se
   unifica el tipo cuando un `affected` mezcla `semver` y `custom`, o se deja el tramo `custom` en
   `raw_ranges`? Es un cambio del conversor (T5), fuera de esta prueba.
