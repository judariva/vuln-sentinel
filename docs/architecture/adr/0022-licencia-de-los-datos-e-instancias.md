---
adr: "0022"
titulo: Licencia de los datos en el modelo, conectores como plugins e instancias
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-003, CMP-005, CMP-007, CMP-018, CMP-019, SRC-002, SRC-003, SRC-006, SRC-013, SRC-014, THR-011, CTL-011]
sustituye: null
---

## Contexto

vuln-sentinel es transversal: el mismo código sirve a varias instancias con derechos distintos
sobre los datos. Hasta ahora la licencia de cada fuente solo vivía en `PLAN.md` §4 y en ADR-0020
(`commercial_use`, `isolation`). No estaba en el modelo de datos, así que nada impedía que un dato
de una fuente de pago acabara en el feed público o decidiera su nivel.

Restricciones: el feed público es gratis, igual para todos y Apache-2.0 (ADR-0011, ADR-0021); el
monitor no guarda datos de clientes (regla 5 de `CLAUDE.md`); VulnCheck está fuera de la v1 por
sus términos (ADR-0020).

## Decisión

1. **Tipos de instancia.** Un solo código, tres configuraciones (`config/instance.*.yaml`):

   | Instancia | Clases admitidas | Conectores |
   |---|---|---|
   | `public` | solo `open` | solo fuentes redistribuibles |
   | `clients` | `open` y `restricted` | las abiertas y las de pago que el operador tenga licenciadas |
   | `third_party` | `open` y `restricted` | las abiertas y las de pago con la licencia de quien la opere |

   Todo el código se publica, también los conectores de fuentes de pago: el código de un conector
   no es el dato de la fuente. Cada instancia activa solo los conectores para los que tiene
   licencia.

2. **Cada dato lleva su licencia.** `source`, `vulnerability`, `affected_product`, `signal` y
   `ai_call` (el dosier cita fuentes) llevan `license_class` y `licensee`; `vulnerability` y
   `affected_product` llevan además `source`:
   - `open`: redistribuible; `licensee` es NULL;
   - `restricted`: solo para quien tenga la licencia `licensee` (un identificador opaco: el
     contrato no vive en el repo).

   Un `CHECK` lo impone en la base de datos y `Record` lo impone en código. La clase de licencia es
   ortogonal al aislamiento de ADR-0020 (`link_only`, `facts_only`, `excluded`): una fuente
   `link_only` guarda solo el identificador y el enlace, que son `open`.

3. **Conectores como plugins** (CMP-018). Interfaz común en `src/vs/sources/base.py`: `name`,
   `license_class`, `licensee`, configuración requerida, `fetch()` y `normalize()`, y un registro
   por nombre. Se activan en la configuración de la instancia. Uno nuevo no toca el núcleo. El
   núcleo solo consume `records()`, que rechaza cualquier registro con una licencia distinta de la
   declarada por el conector. La configuración no lleva secretos: nombra la variable de entorno.

4. **Feed según derechos y nivel por feed** (CMP-019). Cada feed (público, por cliente) filtra las
   señales por lo que su audiencia puede recibir, y el nivel A/B/C se calcula **solo con las señales
   permitidas en ese feed**. Si el único A de una CVE sale de una fuente `restricted`, en el feed
   público esa CVE sale con el nivel que den las señales abiertas. `nivel_final = max(determinista,
   IA)` (CTL-001) se aplica dentro de cada feed; la IA de la instancia pública solo ve datos `open`.

5. **La instancia pública nunca guarda `restricted`** (CTL-011, THR-011). Tres guardas:
   - la configuración `public` no puede admitir `restricted` ni declarar licencias;
   - cargar un conector `restricted` lanza un error antes de crear ninguno;
   - el almacenamiento rechaza las filas no admitidas y una auditoría falla si encuentra alguna.

   `tests/test_license_rights.py` lo comprueba con conectores **sintéticos**.

6. **Multi-cliente, en una fase posterior a la F4.** En la instancia de clientes, cada cliente
   tendrá su clave de acceso al feed y su filtro de derechos (su audiencia). Si algún día se guarda
   inventario de cliente, se separa por diseño. En la v1 no se guarda ninguno y solo existe la
   instancia pública.

7. **Conector de VulnCheck.** Se puede escribir y probar, pero **solo con fixtures sintéticos**
   (ningún dato real en git), declarado `restricted` y desactivado en la instancia pública. Solo se
   activa en una instancia que tenga una licencia comercial real. ADR-0020 sigue vigente para la
   instancia pública.

8. **Señal de explotación abierta**, para que el A público sea fuerte sin fuentes de pago. Sube a A,
   de forma determinista, cualquiera de estas señales `open`:
   - `kev_cisa` (SRC-002);
   - SSVC `exploitation = active` (Vulnrichment, vía el ADP de CISA);
   - la marca de explotación de la EUVD (SRC-014), **solo cuando su licencia esté verificada**
     (ver Evidencia);
   - `vendor_exploited`: la marca de explotación del aviso oficial del fabricante o de su PSIRT
     (por ejemplo, «Exploited: Yes» en la guía de actualizaciones de Microsoft) (SRC-013). Es un
     hecho con enlace (`facts_only`), no se copia texto;
   - el agente, cuando cita un aviso oficial que dice «explotada» y el verificador comprueba la
     cita (CTL-002).

   La regla vive en `src/vs/rules/` (T4). Hoy `src/vs/feed/rights.py` lleva un nivel de juguete
   solo para probar el filtro.

## Clase de cada fuente en la instancia pública

Se mantiene la clasificación de `PLAN.md` §4 y ADR-0020. Con el modelo de donaciones se releyeron
los términos de las fuentes aisladas por «uso comercial»:

- **INCIBE-CERT: sin cambio, `link_only`.** El aviso legal, además de exigir que «No se pretenda un
  uso comercial», añade en la misma condición: «quedando expresamente prohibidas su distribución,
  comunicación pública, transformación o descompilación», y «Cualquier otro uso habrá de ser
  comunicado y autorizado por INCIBE, previa y expresamente». Publicar su texto en un feed es
  distribución y comunicación pública, aunque no haya ánimo de lucro. La cita no permite
  reclasificar. Solo una autorización expresa de INCIBE lo cambiaría.
- **OSV.dev, registros de Chainguard/Wolfi (CC-BY-NC-ND 4.0): sin cambio, `excluded`.** El feed
  público es Apache-2.0 y cualquiera puede usarlo con fines comerciales; la licencia solo permite
  usos «not primarily intended for or directed towards commercial advantage or monetary
  compensation» y prohíbe compartir material adaptado. Que el proyecto se sostenga con donaciones
  no cambia lo que hace quien consume el feed.
- **VulnCheck: sin cambio.** No está aislado por «uso comercial», sino porque sus términos prohíben
  ofrecer los datos gratis o con licencia abierta (ADR-0020). En la instancia pública queda
  excluido; en una de clientes con licencia es `restricted`.

Las demás fuentes de §4 son `open` (con el aislamiento que ya tenían). Para la instancia de
clientes, que es comercial, vale la clasificación anterior.

## Alternativas descartadas

- **Una sola instancia con un flag por campo en el feed.** El dato restringido seguiría guardado
  en la instancia pública y bastaría un fallo del filtro para filtrarlo.
- **Repos o ramas distintos por instancia.** Duplica el núcleo y las reglas; el plugin y la
  configuración resuelven lo mismo.
- **Calcular un nivel global y ocultar la causa en el feed público.** El nivel publicado
  derivaría de datos de pago: es lo que ADR-0020 ya descartó.

## Consecuencias

- Cada dato cuesta dos columnas más y un `CHECK`. A cambio, la frontera de licencias es comprobable
  en código, en la base de datos y en un test.
- El nivel deja de ser único por CVE: es por feed. En la v1 solo hay feed público y `alert` sigue
  siendo uno por CVE. Cuando llegue la instancia de clientes, `alert`, `alert_level_history` y
  `rule_evaluation` necesitarán la clave del feed; se decide en esa fase.
- Se pierde la ventaja temporal de las fuentes de pago en el feed público; la métrica «ventaja
  sobre KEV» medirá cuánto aportan las señales abiertas.
- La EUVD no se activa hasta tener su licencia verificada.

## Evidencia

Leído con `curl` el 2026-11-25:

- INCIBE, aviso legal, https://www.incibe.es/aviso-legal (sin fecha de actualización visible):
  «INCIBE autoriza la reproducción total o parcial de los textos y contenidos proporcionados por el
  portal, siempre que concurran todas y cada una de las siguientes condiciones: […] No se pretenda
  un uso comercial, quedando expresamente prohibidas su distribución, comunicación pública,
  transformación o descompilación.» «Cualquier otro uso habrá de ser comunicado y autorizado por
  INCIBE, previa y expresamente.»
- CC BY-NC-ND 4.0, https://creativecommons.org/licenses/by-nc-nd/4.0/legalcode.en: «NonCommercial
  means not primarily intended for or directed towards commercial advantage or monetary
  compensation.» y «produce and reproduce, but not Share, Adapted Material for NonCommercial
  purposes only.»
- ENISA, aviso legal general, https://www.enisa.europa.eu/about-enisa/legal-notice: «Reproduction
  of ENISA material published on this website is authorized, provided the source is acknowledged,
  unless it is stated otherwise.»; «For any use or reproduction of photos or other material that is
  not under the ENISA copyright, permission must be sought directly from the copyright holders.»;
  «In the context of ENISA's IPR policy, the general principle is free access under open licenses.»

**EUVD: SIN VERIFICAR.** El 2026-11-25, https://euvd.enisa.europa.eu/,
https://euvd.enisa.europa.eu/faq y https://euvd.enisa.europa.eu/apidoc devolvían una pantalla
«Application Unavailable» sin texto legal, y https://www.enisa.europa.eu/legal-notice daba 404. El
aviso general de ENISA no dice que se aplique a los datos de la EUVD, que además agregan material
de terceros (registros CVE, avisos de fabricante). No se activa hasta leer sus condiciones.
