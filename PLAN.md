---
estado: aprobado con cambios (revisión del 2026-11-25); revisión 2 aplicada
fecha: 2026-11-25
precedencia: CLAUDE.md > PLAN.md > KICKOFF.md (local/DECISIONS.md es histórico privado)
---

# Plan · vuln-sentinel

Monitor 24/7 de vulnerabilidades nuevas y peligrosas. Producto open source de Juan. El núcleo
corre en Azure; Cloudflare hace de borde. Publica un feed firmado que las herramientas de cada
cliente consultan para cruzarlo con su inventario sin IA.

Convenciones:
- **SIN VERIFICAR**: no comprobado hoy.
- **UNKNOWN**: no se pudo leer.
- **INFERENCIA**: se deduce, no se ha observado.

Toda cifra lleva fecha 2026-11-25 y fuente. Este fichero es público: no lleva IDs, nombres de
recursos internos, IP, correos ni la postura de seguridad de la plataforma (regla 8). La postura
está en `local/`, que no se versiona.

---

## 0. Primer paso: reglas de las decisiones → CLAUDE.md

**Hecho.** Las reglas vivas están en `CLAUDE.md`. Las decisiones originales y la revisión del plan
son histórico privado en `local/`. El resumen público está en
`docs/journey/00-origen-y-decisiones.md`. El detalle de acceso (rutas, variables, comprobación de
tenant) está en `local/ACCESS.md`.

---

## 1. Lo que el diseño necesita de la plataforma (fase 0, solo lectura)

| Necesidad | Estado |
|---|---|
| Región con Claude en Foundry | **Sweden Central** (la única europea con Claude en el catálogo). West Europe no lo tiene |
| Modelos | Haiku 5.5 y Sonnet 5.5 en GlobalStandard, con cuota disponible. Que se puedan desplegar en esta suscripción: lo confirma G-6 |
| Foundry Agent Service con Claude | No soportado ([MS Learn, act. 18-11-2026](https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/limits-quotas-regions)) |
| Container Apps, PostgreSQL Flexible, Key Vault, Log Analytics/Sentinel | Disponibles |
| Workspace de Sentinel para el latido | Disponible (el de la plataforma) |
| Cloudflare: zona, Access con Entra, WAF, Tunnel | Disponibles |
| Cloudflare: plan Workers | UNKNOWN → G-12 |

---

## 2. Arquitectura (D9)

```
          Internet                                Cloudflare (borde)
  clientes / portal ──► vuln.<dominio> ── Worker static assets (front)
                    └──► api.<dominio>  ── caché + WAF ──┐
  admin  ───────────► Access (Entra) ── /admin/* ────────┤
                                                         │ Cloudflare Tunnel (sin origen público)
  Azure · RG propio · Sweden Central ────────────────────┼───────────────────────────────────────
   ACA env (solo Consumption, VNet propia)               ▼
     app  api          (FastAPI, escala 0–1)  ◄── cloudflared (app interna)
     job  ingest       cron */5   colectores → hechos → reglas → alertas
     job  investigate  cron */10  agente para candidatos B/C (D13)
     job  publish      cron */10  feed firmado + cola de aprobación + envío aprobado
     job  daily        cron diario  resumen + agregados de métricas
   PostgreSQL Flexible B1ms (acceso privado)   Key Vault propio (PE, firma del feed)
   Foundry: Claude (identidad gestionada)       App Insights (trazas OTel GenAI)
   Logs Ingestion API → workspace de Sentinel (latido)
  GitHub Actions (fuera de Azure y de Cloudflare) ── vigilante externo del feed (R8)
```

| ADR | Decisión | Por qué |
|---|---|---|
| ADR-001 | Región **Sweden Central** | Única región europea con Claude en Foundry; Container Apps ~30 % más barato que en West Europe ([Retail Prices API](https://prices.azure.com/api/retail/prices)) |
| ADR-002 | **Container Apps Jobs con cron**, sin Service Bus; la cola es la BD (`FOR UPDATE SKIP LOCKED`) | Volumen bajo; una pieza y un coste menos |
| ADR-003 | **PostgreSQL Flexible B1ms**, acceso privado | Relacional, con agregados diarios; ~17 €/mes. Azure SQL serverless no se pausa con ingesta cada 5 min ([free offer](https://learn.microsoft.com/en-us/azure/azure-sql/database/free-offer)) |
| ADR-004 | Origen **sin IP pública**: `cloudflared` como app interna | Ni el WAF ni Access se pueden saltar |
| ADR-005 | Front **React (SPA estática con Vite)** en **Workers static assets** (P-12) | Gratis en estáticos ([doc](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/)); es un consumidor de la API (D10) |
| ADR-006 | **Python 3.13** | Rangos de versión (`univers`, purl), OSV y CSAF |
| ADR-007 | Feed **OSV 1.9.x extendido** | Cruce directo por purl ([spec 1.9.2](https://ossf.github.io/osv-schema/)). CSAF VEX como exportación posterior (CSAF 2.1 aún es CS01) |
| ADR-008 | Firma **ES256 (JWS detached)** con clave no exportable en Key Vault | La clave no sale de KV. Ed25519 en KV Standard: **SIN VERIFICAR** |
| ADR-009 | IA: **Claude en Foundry con identidad gestionada** si G-6 funciona (P-1) | Preferencia D5, sin secretos. Si no: API de Anthropic con clave en KV, a través de un AI Gateway **nuevo y con autenticación** |
| ADR-010 | Agente: **bucle propio con tool use** en un ACA Job | Agent Service no admite Claude; portable; OTel |
| ADR-011 | Licencia **Apache-2.0 para todo el repo**; `NOTICE` con atribuciones de datos; contribuciones con DCO | El modelo de donaciones pide un proyecto 100 % abierto (ADR-018 rechazado) |
| ADR-012 | **Carga inicial de referencia** por fuente, sin alertas (R2) | Evitar la avalancha del primer arranque y la de cada fuente nueva |
| ADR-013 | **B exige impacto mínimo** (R3) | Un exploit de DoS o de fuga de versión no es urgente |
| ADR-014 | Pipeline con **RBAC Administrator con condición** (R9) | Que el pipeline no pueda darse a sí mismo cualquier rol |
| ADR-015 | **Continuidad de la suscripción**: al cambiar su modelo de facturación pasa a pago por uso, a cargo de Juan (P-13) | El producto es 24/7; el coste ya está dimensionado para pago por uso (§14) |
| ADR-016 | **Hosts, nombre y marca en configuración** (P-3) | Objetivo de negocio: migrar a marca y dominio propios cambiando DNS y variables, sin tocar código |
| ADR-017 | **Redes: feed Atom + herramienta existente** de pago con API permitida (**Zernio**, **aceptado** por Juan el 2026-11-25; Upload-Post segunda; Postiz autoalojado como alternativa futura; Buffer descartado) (P-6, J-2) | Sin integrar las API de las redes una a una; lock-in bajo |
| ADR-018 | ~~Open core con FSL-1.1-ALv2~~ → **rechazado** | Sostenibilidad por donaciones, no por venta |
| ADR-019 | **Feed completo + feed de alertas**; índice de cambios paginado y páginas selladas en R2 | El consumidor recibe todas las CVE; las listas solo deciden la urgencia |
| ADR-020 | **Uso comercial de las fuentes**; VulnCheck fuera de la v1; INCIBE y nginx.org solo hechos y enlace (P-5) | Términos comprobados con URL |
| ADR-021 | **Donaciones solo en Bitcoin** (Lightning y on-chain), sin custodia, con una dirección nueva por donación; las recibe Juan como persona física (**aceptado**: lista pregenerada offline + Phoenix con totales manuales) | Sostenibilidad sin vender datos ni acceso; el feed es igual para todos |
| ADR-022 | **Licencia de los datos e instancias** (propuesto): `license_class` (`open`/`restricted`) y `licensee` en cada dato; conectores como plugins; nivel calculado por feed con las señales permitidas; la instancia pública nunca guarda `restricted` | El mismo código sirve a una instancia pública, a una de clientes y a la de terceros |

---

## 3. Contrato del feed (lo más importante)

Base: **OSV 1.9.x**. **Toda CVE** vista es un registro OSV con su nivel (`A`, `B`, `C` o `none`);
las alertas son los registros con nivel A, B o C (ADR-019). Las extensiones van en
`database_specific.vuln_sentinel` (en la raíz) y en el `database_specific` de cada `affected[]`. Un
cliente que solo entienda OSV cruza por purl y rango sin leer la extensión.

```jsonc
{
  "schema_version": "1.9.2",
  "id": "VS-CVE-2026-123007",            // estable: una alerta por CVE, nunca se reutiliza
  "aliases": ["CVE-2026-123007", "GHSA-m4q8-cf44-f42r"],
  "related": ["VS-CVE-2026-123633"],
  "published": "…",                      // cuándo publicó vuln-sentinel la alerta
  "modified":  "…",
  "summary": "nginx HTTP/2: corrupción de memoria con RCE sin autenticación",
  "affected": [{
    "package": { "ecosystem": "Generic", "name": "nginx", "purl": "pkg:generic/nginx" },
    "ranges": [{ "type": "ECOSYSTEM",
      "events": [{"introduced":"1.9.5"},{"fixed":"1.30.7"},{"introduced":"1.31.0"},{"fixed":"1.31.9"}] }],
    "database_specific": {
      "cpe": ["cpe:2.3:a:f5:nginx_open_source:*:*:*:*:*:*:*:*"],
      "product_category": "web-proxy",
      "range_source": "vendor-advisory",     // vendor-advisory | osv | nvd | agent (con cita)
      "purl_derived": true
    }
  }],
  "references": [{ "type": "ADVISORY", "url": "https://nginx.org/en/security_advisories.html" }],
  "database_specific": { "vuln_sentinel": {
    "level": "B",
    "impact_class": "rce",                   // rce | auth_bypass | arbitrary_rw | other (R3)
    "level_reason": ["B.exposed_product:web-proxy", "B.impact:rce", "B.exploit:E4"],
    "level_history": [ {"level":"C","at":"…","reason":["…"]}, {"level":"B","at":"…","reason":["…"]} ],
    "signals": {
      "kev":   {"cisa": false, "observed_at": "…"},
      "ssvc":  {"exploitation":"none","automatable":"no","technical_impact":"total","source_published_at":"…","observed_at":"…"},
      "epss":  {"score":0.447,"percentile":0.988,"delta_7d":0.44,"model":"v4","date":"2026-11-24"},
      "exploits": [{"rule":"E4","url":"…","kind":"exploit","source_published_at":"…","observed_at":"…"}],
      "fix":   {"available": true, "versions": ["1.30.7","1.31.9"]},
      "mitigation": [{"text":"http2 off + reinicio","url":"…"}]
    },
    "sources": [{"name":"cvelistV5","url":"…","source_published_at":"…","observed_at":"…"}],
    "changes": [{"type":"new","at":"…"}, {"type":"poc_added","at":"…","level_from":"C","level_to":"B"}],
    "ai": {"used": false}
  }}
}
```

- Tipos de cambio: `new`, `level_up`, `kev_added`, `poc_added`, `fix_released`, `epss_jump`,
  `range_completed`, `withdrawn`.
- **Dos feeds** (ADR-019). Las listas `exposed-products` y `trusted-exploit-authors` **solo deciden
  la urgencia**, no qué entra:

  | Endpoint | Contenido |
  |---|---|
  | `/v1/feed/all/changes?since=<cursor>` | Índice de **todas** las CVE nuevas o cambiadas (`id`, `modified`, `level`, `type`, `sha256`), a los ~5 min de verlas. 1.000 entradas por página |
  | `/v1/feed/all/changes/{AAAA-MM-DDTHH}.json` | Páginas selladas por hora, inmutables y servidas desde R2; retención de 30 días (después, `410` con el enlace al snapshot) |
  | `/v1/feed/all/snapshot/{fecha}.zip` | Snapshot diario completo, por ecosistema, con un manifiesto firmado |
  | `/v1/feed/alerts/changes?since=` y `/v1/feed/alerts/latest.json` | Solo A, B y C: lo que despierta a alguien |
  | `/v1/vulns/{id}.json` | Registro OSV completo; ETag igual al hash |
  | `/v1/digest/{fecha}.json` | Resumen diario |
  | `/v1/social.atom` | Posts aprobados (ADR-017) |

  Volumen medido (ADR-019): 587 CVE nuevas al día de media (pico de 2.077) y 2.140 modificadas
  (pico de 6.426). El índice ocupa ~0,4 MB al día y ~12 MB en 30 días. Cada documento lleva su
  `.jws`.
- Clave pública: `/.well-known/vuln-sentinel/keys.json` (JWKS con `kid` y rotación).
- Versión del contrato: cabecera `X-VS-Schema: 1.0.0` y `schema/feed-1.0.0.json` en el repo. Un
  cambio incompatible sube la versión mayor y la anterior se sirve 90 días más.
- Firma: JWS detached (RFC 7797) sobre los bytes exactos. Se verifica con `openssl` o con una
  librería JOSE; `examples/verify/` trae un ejemplo.

---

## 4. Fuentes (comprobadas el 2026-11-25)

Columna **«uso comercial»** (ADR-020): comprobada el 2026-11-25 en la URL de los términos. Se
mantiene aunque el proyecto no se venda: el feed lo puede usar cualquiera y el proyecto recibe
donaciones. No es asesoramiento jurídico: antes de activar las donaciones, Juan hace una revisión
legal, que queda fuera de este repo. Las fuentes que no lo admiten se marcan y se aíslan (`excluded`, `link_only`, `facts_only`).

| Fuente | Aporta | Consumo y frecuencia | Límites | Uso comercial (términos) | Estado |
|---|---|---|---|---|---|
| [cvelistV5](https://github.com/CVEProject/cvelistV5) | CVE nuevos y cambios; ADP de CISA (SSVC); PURL (5.2) | Commits de GitHub cada 5 min; zip delta horario como respaldo | GitHub 5.000/h con token | **Sí**, reproduciendo el aviso de copyright de MITRE ([CVE ToU](https://www.cve.org/Legal/TermsOfUse)) | Activo |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Explotación (A). **`dateAdded` es una fecha, sin hora** (R4) | JSON cada 15 min, diff por `cveID` | — | **Sí**, CC0; sin logos de CISA ni del DHS ([LICENSE](https://github.com/cisagov/kev-data)) | Activo (catálogo 2026.11.24, 1.795) |
| VulnCheck KEV | Explotación (A) | — | — | **No en la v1.** Prohíbe ofrecer los datos gratis o con licencia abierta; atribución destacada; sin entrenar IA ni competir ([service-terms](https://vulncheck.com/service-terms), rev. 06-07-2026) | **Excluida** hasta tener permiso por escrito o licencia (ADR-020) |
| [Vulnrichment](https://github.com/cisagov/vulnrichment) | SSVC | A través del ADP de cvelistV5; el repo como respaldo | — | **Sí**, CC0 | Activo |
| [EPSS](https://www.first.org/epss/data) | Probabilidad y salto | CSV diario después de las 13:45 UTC | La API no es para volcados masivos | **Sí**, «Is EPSS free to use? Yes»; atribución pedida ([FAQ](https://www.first.org/epss/faq)) | Modelo v4 |
| [GHSA](https://docs.github.com/en/rest/security-advisories/global-advisories) | Rangos de ecosistemas | `?modified=` cada 15 min | Límites de la API de GitHub | **Sí**, CC-BY 4.0 (enlazar el aviso) ([términos](https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features)) | Activo |
| [OSV.dev](https://google.github.io/osv.dev/data/) | Rangos | `modified_id.csv` | — | **Con condiciones**: licencia por fuente. **Chainguard/Wolfi excluida** (CC-BY-NC-ND); Ubuntu y Alpine CC-BY-SA, marcadas `share_alike` | Activo |
| [NVD 2.0](https://nvd.nist.gov/developers/start-here) | CPE/CVSS (solo KEV y software crítico) | Bajo demanda | 50/30 s con key | **Sí**, dominio público; aviso fijo y sin sugerir aval | [Recortado desde el 15-04-2026](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth) |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Exploit (E1); el **tipo** de módulo distingue exploit, auxiliary y DoS | `modules_metadata_base.json`, diario | — | **Sí**, BSD-3-Clause; conservar el aviso de Rapid7 | Activo |
| [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) | Exploit (E2); el **tipo** (`dos`, `remote`, `webapps`, `local`) | `files_exploits.csv`, diario | — | **Con condiciones**: GPL-2.0. Solo metadatos (identificador, tipo y enlace); no se redistribuye el CSV. Términos de OffSec: SIN VERIFICAR (403) | Activo |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | Detectable (señal, no exploit) | `cves.json` cada hora | — | **Sí**, MIT | Activo |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Candidatos a PoC | JSON por CVE, cada hora | «Be careful Malware» | **Sí**, CC0; el código de cada PoC conserva su licencia: se enlaza, no se aloja | Activo |
| [Búsqueda de GitHub](https://docs.github.com/en/rest/search/search) | PoC recientes de candidatos | Solo candidatos B/C | 30/min con token | **Con condiciones**: sin compartir tokens para superar los límites; la reventa a gran volumen puede exigir suscripción ([ToS §H](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service)) | — |
| CERT-EU | Avisos | RSS | — | **Sí**, CC-BY 4.0 ([legal notice](https://cert.europa.eu/legal-notice)) | Activo |
| INCIBE-CERT | Avisos | RSS | — | **No** sin autorización: «No se pretenda un uso comercial»; sin transformación ([aviso legal](https://www.incibe.es/aviso-legal)) | **Solo enlace** (`link_only`) |
| nginx.org y avisos de fabricante sin licencia | Rangos, fix, «explotado» | RSS/CSAF (nginx.org, Fortinet, Palo Alto, Cisco, MSRC, Red Hat, Siemens, CISA) | — | nginx.org: «© F5, Inc. All rights reserved». El resto, por fabricante (SIN VERIFICAR) | **Solo hechos y enlace** (`facts_only`) |
| OpenCVE | — | **Descartado** | Free 100/h | BSL | — |
| EUVD (ENISA) | Explotación (señal abierta de A, ADR-022) | API, frecuencia por decidir | SIN VERIFICAR | **SIN VERIFICAR**: las páginas de la EUVD no cargaban el 2026-11-25; el aviso general de ENISA autoriza reproducir «provided the source is acknowledged, unless it is stated otherwise» ([legal notice](https://www.enisa.europa.eu/about-enisa/legal-notice)) pero no dice que cubra la EUVD | **Pendiente**: no se activa hasta leer sus condiciones |

**`license_class` por fuente (ADR-022).** Es la clase del dato que se **guarda**, ortogonal al
aislamiento (`link_only` guarda solo el identificador y el enlace, que son `open`).

| Fuente | Instancia pública | Instancia de clientes |
|---|---|---|
| cvelistV5, CISA KEV, Vulnrichment, EPSS, GHSA, NVD, Metasploit, nuclei-templates, PoC-in-GitHub, búsqueda de GitHub, CERT-EU | `open` | `open` |
| OSV.dev | `open`, **sin** Chainguard/Wolfi (`excluded`, CC-BY-NC-ND) | igual |
| Exploit-DB | `open`, solo metadatos | igual |
| INCIBE-CERT | `open`, `link_only` (sin cambio tras releer sus términos con el modelo de donaciones: ADR-022) | igual |
| nginx.org y avisos de fabricante | `open`, `facts_only` | igual |
| EUVD (ENISA) | Pendiente (licencia SIN VERIFICAR) | Pendiente |
| VulnCheck KEV | **Excluida** (ADR-020); el conector no se carga | `restricted`, `licensee` = la licencia comercial, solo si existe |

**Fail-closed.** Cada ejecución queda en `source_run`. Si la fuente falla o su dato tiene más
antigüedad que el umbral, pasa a **UNKNOWN**. Nunca se publica «sin novedades».

---

## 5. Criterio A/B/C (reglas comprobables, `src/vs/rules/`)

### 5.1 Qué es «nuevo» y la carga inicial (R2, ADR-012)

- **Carga inicial de referencia, por fuente.** La primera ejecución completa de cada fuente
  (`source.baseline_completed_at`) guarda hechos y señales con `baseline = true` y **no genera
  alertas**. Lo mismo vale para una fuente que se añade más tarde: tiene su propia carga inicial y no
  provoca una avalancha.
- **Una CVE es evaluable para alertar** si cumple al menos una de estas condiciones:
  - (a) `vulnerability.source_published_at` cae en los últimos **N = 14 días**;
  - (b) recibe una señal **nueva**: una señal cuyo `observed_at` es posterior al
    `baseline_completed_at` de su fuente y que no estaba en la carga inicial.

  Una CVE antigua que hoy entra en KEV o recibe un exploit es un cambio y alerta.
- N es configurable. El valor de 14 días cubre el retraso habitual entre publicación y primer
  exploit. Se revisa con datos al acabar la F1b.

### 5.2 Niveles

El nivel solo sube. Bajarlo exige un acto manual de Juan, que queda registrado.

- **A, inmediato**: se cumple cualquiera de estas condiciones:
  - `kev.cisa` (VulnCheck KEV queda fuera de la v1 por sus términos: ADR-020);
  - `ssvc.exploitation = active`;
  - el agente cita un aviso oficial que dice «explotada» y el verificador comprueba la cita.
- **B, urgente**: ¬A ∧ `producto_expuesto` ∧ `impacto_minimo` ∧ `exploit_funcional(impacto)`.
- **C, vigilar**: ¬A ∧ ¬B ∧ `producto_expuesto` ∧ `rce_sin_auth` ∧ ¬`exploit_funcional`.
- Lo demás va al resumen diario.

**`impacto_minimo`** (R3, ADR-013). Es determinista y calcula `impact_class`:

| Clase | Criterio (cualquiera) |
|---|---|
| `rce` | CWE ∈ {77, 78, 94, 95, 502, 787, 416, 190, 191, 122, 120, 917, 1336} con CVSS C:H/I:H, o `technical_impact = total` |
| `auth_bypass` | CWE ∈ {287, 288, 290, 294, 306, 862, 863, 639, 1390} con `PR:N` |
| `arbitrary_rw` | CWE ∈ {22, 23, 36, 73, 434, 611, 918} con C:H o I:H |
| `other` | El resto, incluidos **solo DoS** (CVSS C:N/I:N, o CWE ∈ {400, 770, 835, 674, 1333}) y las fugas de versión o de información de bajo impacto |

B exige `impact_class ≠ other`. Además, el exploit tiene que corresponder a ese impacto:
- un módulo `auxiliary/dos/*` de Metasploit no cuenta;
- una entrada de Exploit-DB de tipo `dos` tampoco;
- con E4 y E5, el agente clasifica el impacto del código y **no puede declarar más impacto que el
  del CVE**.

**`producto_expuesto`**: el vendor/product del CNA, el CPE o el purl coincide con
`config/exposed-products.yaml`. La lista se mantiene por PR revisado e incluye categoría, alias y
CPE.

**`rce_sin_auth`**: `impact_class = rce` ∧ CVSS `AV:N/PR:N/UI:N`.

### 5.3 «Exploit público funcional»

- **E1**: módulo de Metasploit de tipo `exploit/` que referencia el CVE.
- **E2**: entrada de Exploit-DB de tipo distinto de `dos`, con el CVE.
- **E3**: `ssvc.exploitation = poc`.
- **E4**: repositorio cuyo autor está en `config/trusted-exploit-authors.yaml`, **o** que el
  registro CVE o el aviso del fabricante enlazan como exploit.
- **E5**: el agente lee el código **sin ejecutarlo** y confirma, con citas a líneas concretas, que
  implementa el exploit con el impacto del CVE. Solo puede llevar de C a B.

**Lista de autores de confianza (R7).** Se define por un **criterio escrito** antes de mirar ningún
caso. La v1 es la unión de dos fuentes:
- (i) organizaciones y personas con al menos un módulo `exploit/` aceptado en Metasploit en los
  últimos 24 meses (campo `author` del metadata);
- (ii) organizaciones con avisos de vulnerabilidad propios publicados en los últimos 24 meses y
  acreditadas como descubridoras en registros CVE (campo `credits`).

La lista se **genera con un script reproducible** a partir de esos datos, se commitea **antes** que
el fixture de nginx2root y Juan la revisa (P-10). Las altas y bajas manuales llevan motivo en el
commit.

**PoC falsos o con malware.** Un repositorio que no cumple E1–E5 queda como `poc_unverified`: se
muestra, pero no sube el nivel. Se marca `poc_suspicious` (excluido y con aviso en el portal) si
tiene cualquiera de estas señales:
- binarios o releases ejecutables;
- blobs base64 u ofuscados de más de N KB;
- `curl|sh` o descargas de dominios fuera de la lista permitida;
- una cuenta con menos de 30 días;
- un README sin código;
- es un fork de otro PoC.

El código nunca se clona ni se ejecuta.

---

## 6. nginx2root · cronología y cuándo salta B (R6)

| UTC | Hecho | Tipo | Fuente |
|---|---|---|---|
| 18/11 (sin hora) | nginx publica 1.30.7 y 1.31.9 | Hecho | nginx.org |
| 18/11 11:16:51 | Rapid7 crea el repo `sfewer-r7/CVE-2026-123007` | Hecho (`created_at`) | API de GitHub |
| 18/11 15:23:27 | Último push del repo (`pushed_at`) y publicación de CVE-2026-123633 | Hecho | API de GitHub, cveawg |
| 18/11 15:23:29 | Publicación de CVE-2026-123007 | Hecho | cveawg |
| ? | El repo pasa a público y la búsqueda de GitHub lo indexa | **UNKNOWN**: la API no lo dice | — |
| 18/11 16:18 | Llega a NVD, con la etiqueta «Exploit» en la referencia de Rapid7 | Hecho | NVD |
| 18/11 17:30 | Aviso CERT-EU 2026-022 | Hecho | CERT-EU |
| 25/11 | No está en KEV; sin explotación confirmada | Hecho | CISA, Sophos, Cloudflare |

Comportamiento esperado:
1. **C hacia las 15:30Z.** Es una INFERENCIA a partir del ciclo de 5 min y del retraso de
   cvelistV5. Se justifica porque la coincidencia es con nginx (web-proxy) y por `AV:N/PR:N` con
   CWE-787 y CWE-416, que dan `impact_class = rce`.
2. **B entre las 15:35 y las 15:50Z: INFERENCIA.** Depende de cuándo pasó el repo a público y de
   cuándo lo indexó la búsqueda, y ninguno de los dos datos es observable.
3. **Lo defendible: B como tarde a las 16:18Z**, por la etiqueta «Exploit» de NVD (E4 por la
   referencia), sin depender de la lista de autores. Es B el mismo día.

La prueba de F1a es una **reconstrucción**: snapshots creados a partir de los datos publicados, no
grabaciones de lo que devolvían las API el 18/11. Se llama así en el código, en la prueba y en la
bitácora. La prueba real es el **siguiente caso en vivo** tras la F1b.

---

## 7. IA: un agente y sus controles (D13, D14)

**Dónde entra.**
- **Agente investigador**, para candidatos B y C sin explotación confirmada. Lee el aviso, lee el
  PoC, completa los rangos y el fix, confirma la exposición y deja un expediente con citas.
- **Redacción**: una llamada con esquema.
- Con A no interviene.

**Modelos y precio** ([Anthropic pricing](https://platform.claude.com/docs/en/about-claude/pricing);
mismo precio en Foundry, facturado en CCU:
[MS Learn](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/claude-models-billing)).

| Uso | Modelo | Entrada / salida (USD por MTok) |
|---|---|---|
| Agente | Sonnet 5.5 | 2 / 10 |
| Redacción | Haiku 5.5 | 0,10 / 0,50 (prompts ≤ 100.000 tokens) |

- Ojo: el tokenizador nuevo genera unos +30 % de tokens.
- Estimación para el agente: 10 candidatos/día × ~40.000 tokens de entrada y 4.000 de salida
  ≈ 36 USD/mes.
- **Tope duro: 1,5 USD/día**, aplicado en código.

**Amenazas y controles.** Versiones fijadas: [MITRE ATLAS 5.6.0](https://github.com/mitre-atlas/atlas-data)
y [ATT&CK v20.1 (13-10-2026)](https://attack.mitre.org/resources/versions/). `AML.T0051.001`
(«LLM Prompt Injection: Indirect») está comprobada en ATLAS 5.6.0.

| Amenaza | Control | Prueba |
|---|---|---|
| Inyección indirecta desde avisos, README de PoC o issues (OWASP LLM01; ATLAS AML.T0051.001) | Contenido externo delimitado como datos; herramientas de solo lectura; sin red libre | `eval/injection-advisory`: nivel sin cambios y sin llamadas fuera de la lista |
| La IA baja el nivel o se lo inventa (LLM09) | `nivel_final = max(determinista, ia)` en código; los intentos se registran | Test unitario + métrica |
| La IA infla el impacto para forzar B | El agente no puede declarar más `impact_class` que el del CVE | Caso de evaluación |
| Citas inventadas | Verificador determinista: descarga la URL permitida y busca la cita literal normalizada | Casos con cita falsa |
| Exfiltración o SSRF (LLM06) | Dominios permitidos, solo GET | Test de herramienta |
| Código malicioso del PoC | Se lee como texto por la API; nunca se clona ni se ejecuta; el contenedor no tiene intérprete de shell | Revisión en CI |
| Consumo desbocado (LLM10) | 12 pasos, 60.000 tokens por candidato y 1,5 USD/día; si se supera, `needs_human` | Bucle simulado |
| Salida mal formada | JSON Schema; si no valida, se rechaza | Test |
| Publicación no autorizada | El agente no publica; las redes pasan por la cola de Juan | Test de permisos |

**Conjunto de evaluación** (`eval/`, en CI ante cualquier cambio de prompt, modelo o herramienta):
- nginx2root;
- 10 entradas de KEV;
- ruido (una USN de kernel);
- **DoS con exploit público en un producto expuesto → no B** (R3);
- aviso con inyección;
- PoC falso con malware.

Umbrales: 0 bajadas de nivel, 0 citas inventadas aceptadas y 100 % en inyección.

---

## 8. Modelo de datos (PostgreSQL)

Todo hecho lleva `source_published_at` y `observed_at`. El esquema es el modelo de SQLAlchemy de
`src/vs/model/schema.py`, con migraciones de Alembic en `src/vs/model/migrations/`
(`uv run python -m vs.model.migrate upgrade head`, URL en `VS_DATABASE_URL`). El borrador
`schema-draft.sql` de la F0 se retiró. Las consultas de las métricas están en
`docs/metrics/queries.sql` (R5) y `tests/test_db.py` las ejecuta contra PostgreSQL. `verdict` lleva
un `id` de clave primaria que el borrador no tenía.

| Tabla | Campos clave |
|---|---|
| `source` | `name` (PK), `baseline_completed_at`, `freshness_threshold`, `license_class`, `licensee` |
| `source_run` | id, source, `started_at`, `finished_at`, status (ok, partial, unknown), `items_seen`, `items_new`, error, `last_item_published_at` |
| `vulnerability` | `cve_id` (PK), cna, cvss (vector y fuente), cwe[], `impact_class`, `source_published_at`, `observed_at`, `withdrawn_at`, `baseline` |
| `affected_product` | id, `cve_id`, vendor, product, cpe, purl, ecosystem, `ranges` (jsonb), `range_source`, `category`, timestamps |
| `signal` | id, `cve_id`, `kind`, `value` jsonb, source, url, `baseline`, timestamps. Solo inserción |
| `rule_evaluation` | id, `cve_id`, `evaluated_at`, `trigger_signal_id`, `eligible` (5.1), `exposed`, `impact_class`, `exploit_rule`, `result_level` (A, B, C o none), `rules_version`. **Una fila por evaluación** (R5) |
| `alert` | `alert_id`, `cve_id`, level, `reason[]`, status, `first_published_at`, `modified_at` |
| `alert_level_history` | `alert_id`, `level_from`, `level_to`, `reason[]`, `trigger_signal_id`, `decided_by`, `at` |
| `ai_call` | id, `alert_id`, kind, model, `proposed_level`, `final_level`, tokens, `cost_usd`, `trace_id`, `dossier`, `blocked_downgrade` |
| `publication` | id, `alert_id`, channel, status, `approved_by`, `approved_at`, `sent_at`, `external_ref` |
| `verdict` | `alert_id`, verdict (útil o ruido), nota, `at` |
| `metric_daily` | fecha, métrica, dimensión, valor |

**Licencia de los datos (ADR-0022).** `source`, `vulnerability`, `affected_product`, `signal` y
`ai_call` llevan `license_class` (`open` o `restricted`) y `licensee`, con un `CHECK`: `restricted`
exige `licensee` y `open` lo prohíbe. `vulnerability` y `affected_product` llevan además `source`.
La instancia pública nunca guarda filas `restricted` (`src/vs/instance.py`,
`tests/test_license_rights.py`).

---

## 9. Métricas v1 (D11)

Se calculan sobre la BD y se precalculan cada día en `metric_daily`. Las consultas están en
`docs/metrics/queries.sql`.

| Grupo | Métrica | Definición |
|---|---|---|
| Qué detecta | Embudo | Ingeridas (`vulnerability`) → elegibles (`rule_evaluation.eligible`) → candidatas (expuestas con `impact_class ≠ other`) → A, B o C (`result_level`), por día |
| | Reparto | Por CWE agrupado, por categoría y por fabricante; cambios por tipo |
| | **Feed completo frente a alertas** (ADR-019) | CVE publicadas en `all` frente a CVE con nivel A, B o C, por día. Es el embudo visto desde fuera |
| Qué tan rápido | Tiempo de detección | `alert.first_published_at − min(source_published_at)` de la CVE, p50 y p95 por nivel |
| | **Ventaja sobre KEV** (R4) | `observed_at` de la señal `kev_cisa` menos la primera alerta B o C de la CVE. **Precisión: ±15 min** (sondeo); `dateAdded` de KEV es solo una fecha y no se usa para restar |
| | Escalado | De C a B o A, frente al `observed_at` de la señal que lo provocó |
| Qué tan bien | Precisión | Según el veredicto |
| | **Fallos** | Altas de KEV (posteriores a la carga inicial) en productos expuestos sin alerta B o A previa |
| | IA | Confirmaciones e intentos de bajar el nivel bloqueados |
| Salud | Fuentes | Estado y antigüedad de cada fuente; latido; coste de IA por día; publicaciones pendientes |
| **Transparencia** | **Coste del proyecto** | Coste mensual real (Azure Cost Management por API sobre el RG y facturación de Cloudflare por API, en `cost_daily`) frente a lo recibido en donaciones (`donation_received`: importe en sats, fecha y canal, **sin datos del donante**, leído de la cadena o del servidor de pagos). Con las donaciones desactivadas, solo el coste |

---

## 10. Portal (D10)

| Pantalla | Acceso | Contenido |
|---|---|---|
| Hoy | Público | Alertas del día por nivel, con los cambios |
| Detalle de alerta | Público | Productos y rangos, señales, línea de tiempo con las dos marcas de tiempo, fuentes, expediente de IA |
| Métricas | Público | Catálogo de la sección 9 |
| **Coste del proyecto** | Público | Coste mensual real frente a lo recibido (§9); con las donaciones desactivadas, solo el coste |
| Apoya el proyecto | Público, solo con `donations.enabled` | Cómo donar (Lightning y on-chain con una dirección nueva por donación) y reconocimiento a quien dona y lo pide. Nunca da datos antes ni mejores |
| Fuentes | Access | Salud, ejecuciones y UNKNOWN |
| Administración | Access | Cola de aprobación, veredicto, coste de IA y trazas |

La API valida además el JWT de Access (`Cf-Access-Jwt-Assertion`).

---

## 11. Vigilancia

- **Latido.** Cada job, al terminar, envía `VsHeartbeat` al workspace de Sentinel por la Logs
  Ingestion API con su identidad gestionada.
- **Reglas en Sentinel**:
  - sin latido de `ingest` durante 20 min;
  - una fuente en UNKNOWN más de 2 h;
  - coste de IA por encima del 80 % del tope.
- **Vigilante del vigilante, dentro de Azure**: una alerta de Azure Monitor sobre `SentinelHealth`.
- **Vigilante externo e independiente de Azure (R8).** Un workflow programado de GitHub Actions cada
  30 min:
  1. lee la página «head» de `/v1/feed/all/changes` a través de Cloudflare;
  2. verifica la firma JWS con la clave pública;
  3. comprueba que `modified` tenga menos de 30 min y que ninguna fuente lleve más de 2 h en UNKNOWN.

  Cubre también Cloudflare, el Tunnel y la clave. Limitación declarada: los cron de Actions pueden
  retrasarse varios minutos en momentos de carga.
- **Avisos (P-9): correo y ntfy desde los dos vigilantes.**
  - Azure: el grupo de acciones (G-8) avisa por correo y por webhook al tema de ntfy.
  - GitHub Actions: el fallo del workflow avisa por correo (nativo de GitHub) y un paso
    `if: failure()` publica en ntfy.

  El tema de ntfy y su token van en los secrets (regla 8). Se usa ntfy.sh con un tema de nombre
  aleatorio y con control de acceso, o una instancia propia (SIN VERIFICAR: las condiciones del
  plan gratuito de ntfy.sh).
- **Tope de IA en código**: 1,5 USD/día.

---

## 12. Publicación (D8)

- **Feed firmado.** Se regenera en cada ciclo con cambios. TTL de 60 s en Cloudflare y purga por URL
  al publicar.
- **Resumen diario.** A las 07:00 Europe/Madrid, como `/v1/digest/{fecha}.json` y como página del
  portal. Incluye las fuentes en UNKNOWN.
- **Enlace «apoya el proyecto»** en el resumen y en los posts, con el mismo interruptor
  `donations.enabled`. El enlace apunta a la página del portal, nunca a una dirección. Las
  direcciones, la xpub y los enlaces de donación van en configuración y secrets, nunca en git.
- **Teams, como consumidor de ejemplo** (`examples/teams-consumer/`, P-8). Lo ejecuta el
  consumidor:
  1. lee `/v1/feed/all/changes?since=` o `/v1/feed/alerts/changes?since=`;
  2. verifica la firma;
  3. filtra por su inventario;
  4. envía una Adaptive Card 1.2 a un webhook de Workflows
     ([MS Learn](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)).

  **Se prueba contra un receptor de webhook local** (`examples/teams-consumer/receiver/`). Valida
  el esquema de la tarjeta, el límite de 28 KB y el reintento ante un 429. El primer consumidor
  real vive en el entorno de quien consume y lee el feed público como cualquier otro: no se
  construye ni se configura en este repo, y **aquí no se guarda ninguna URL de webhook de
  terceros**.
- **Redes: no se integran sus API una a una (P-6, ADR-017).**
  1. vuln-sentinel redacta el borrador con Haiku sobre una plantilla fija. Solo A y B, como máximo
     3 al día por canal.
  2. Juan lo aprueba en Administración.
  3. El post aprobado se publica en **`/v1/social.atom`**, que es la fuente canónica y va firmada.
  4. En el momento de la aprobación, un adaptador de una sola llamada (`SocialPublisher`) invoca
     la API de la herramienta: **Zernio** (ADR-017, aceptado por Juan el 2026-11-25). Sus términos permiten
     publicar por API y no tienen ninguna cláusula contra la automatización. Cuesta ~6 USD/mes con
     3 canales, y X se paga al precio de X desde un saldo prepago, sin credenciales propias.
     Segunda opción: Upload-Post. Alternativa futura: Postiz autoalojado. **Buffer, descartado**
     por la cláusula 4.2(n) de sus API Terms (J-2).
  5. La herramienta reparte a X, Bluesky y **LinkedIn con el perfil personal** (P-7).

  - El post de X va **sin URL**: 0,015 USD frente a 0,20 USD con URL
    ([docs.zernio.com](https://docs.zernio.com/platforms/twitter)). Alerta de saldo bajo de X.
  - Las plantillas de los posts leen la marca y los hosts de configuración (ADR-016).

---

## 13. Pruebas

| Prueba | Qué demuestra |
|---|---|
| **Carga inicial → 0 alertas** (R2) | La primera ejecución contra snapshots completos de KEV, Exploit-DB, Metasploit y nomi-sec no genera ninguna alerta. Una señal nueva sobre una CVE antigua tras la carga inicial sí alerta |
| **Fuente nueva → 0 alertas** | Añadir una fuente con su histórico no dispara alertas |
| **Reconstrucción de nginx2root** (R6) | Con snapshots reconstruidos y reloj simulado: C tras la publicación y B **como tarde con la señal de NVD de las 16:18Z**. La B anterior por búsqueda de GitHub solo se afirma si la lista de autores (commiteada antes, R7) lo permite. Rangos 1.30.7/1.31.9 en el feed |
| **DoS con exploit → no B** (R3) | Un CVE solo de DoS en nginx con módulo `auxiliary/dos` y entrada de Exploit-DB de tipo `dos` → `impact_class = other` → solo resumen |
| Casos de KEV | A al entrar en KEV; ventaja sobre KEV calculada con `observed_at` |
| **Ruido** | Una USN de kernel con cientos de CVE → 0 alertas A, B o C salvo que alguna esté en KEV |
| **Fallo de fuente** | Timeout, 500, JSON corrupto o dato viejo → UNKNOWN visible; nunca «sin novedades» |
| **CVE fuera de las listas → feed completo** (ADR-019) | Una CVE de un producto que no está en ninguna lista aparece en `all` con `level: none` **antes de 10 minutos** |
| **Fuente excluida → fuera del feed** (ADR-020) | Una fuente con `isolation: excluded` no aporta ningún dato al feed; una `link_only` solo aporta enlaces |
| Paginación | El cursor es estable con inserciones concurrentes; las páginas selladas no cambian; un cursor de más de 30 días recibe `410` con el enlace al snapshot |
| Hosts | Ningún host real en el código ni en los fixtures (ADR-016; `VS_FORBIDDEN_HOSTS` en CI) |
| Monotonía | Tests basados en propiedades: el nivel nunca baja |
| Contrato | JSON Schema + OSV 1.9; firma verificada con openssl |
| Métricas | Las consultas de `docs/metrics/queries.sql` se ejecutan contra el esquema en CI (desde F1a) |
| IA | Conjunto de evaluación en CI |
| Arquitectura | Las vistas solo usan IDs de `architecture.yaml` |

---

## 14. Coste mensual (EUR, 1 USD ≈ 0,90 EUR, Sweden Central)

| Partida | €/mes | Nota |
|---|---|---|
| Container Apps Jobs (4) | ~0–2 | Concesión mensual gratuita de 180.000 vCPU·s ([pricing](https://azure.microsoft.com/en-us/pricing/details/container-apps/)) |
| API (0–1) + cloudflared (1 réplica mínima, 0,25 vCPU) | ~6 | Cargo de «Environment Management» con VNet: **SIN VERIFICAR** |
| PostgreSQL B1ms + 32 GB | ~17 | Backups de 7 días incluidos |
| Key Vault + endpoint privado | ~7 | Endpoint privado: **SIN VERIFICAR** |
| GHCR | 0 | Alternativa: ACR Basic, ~4,6 € |
| Log Analytics + Sentinel (~1 GB) + reglas | ~6 | 5,59 USD/GB en el precio simplificado ([billing](https://learn.microsoft.com/en-us/azure/sentinel/billing)) |
| IA: Sonnet 5.5 + Haiku 5.5 | ~33 | Tope de 1,5 USD/día (~41 €) |
| Cloudflare | 0 | Access gratis hasta 50 usuarios; con Workers Paid, +4,5 € |
| Redes: Zernio + saldo de X | ~7 | 3 cuentas: 2 gratis + 1 × 6 USD/mes ([pricing](https://zernio.com/pricing)); X sin URL ≈ 1,35 USD/mes (90 posts) |
| Cloudflare R2 (páginas selladas y snapshot) | ~0 | Plan gratuito de 10 GB y salida de datos gratuita; el corpus completo comprimido cabe |
| ntfy | 0 | Plan gratuito o instancia propia (SIN VERIFICAR) |
| GitHub Actions (CI y vigilante externo) | 0 | Repo público |
| **Total** | **≈ 70–85 €** (peor caso ≈ 98 €) | Cabe en D6 |

Palancas:
- agente con Haiku si cumple la evaluación (P-2, −30 €);
- posts de X sin URL (ya es el valor por defecto; con URL serían +15 €);
- KV sin endpoint privado, que entraría **como ADR** si G-4 se complica, no como atajo.

Alerta de presupuesto a 80 € (G-9).

---

## 15. Fases

| Fase | Contenido | Termina cuando |
|---|---|---|
| **F0 · arranque (local)** | Reglas en `CLAUDE.md`; estructura; CI; licencia y `NOTICE`; plantillas de ADR; ADR-001…020; `architecture.yaml` inicial con su test; `docs/journey/`; `STATE.md`; criterio de `trusted-exploit-authors` (R7); DDL en borrador y consultas de métricas (R5) | `uv run pytest` y `ruff` en verde en local. **Hecho** (commit inicial local) |
| **Repo privado** | `gh repo create` privado; `CONTRIBUTING` con DCO. Todo Apache-2.0 (ADR-011). Protección de `main` (PR obligatorio y CI en verde) **bloqueada en privado con el plan gratuito de GitHub**. Sin GitHub Pro (J-8): regla 9 de `CLAUDE.md` + hook `pre-push` local; la protección de rama se aplica al hacerlo público, al cerrar la F1a (J-7) | Hecho tras la búsqueda de fugas sobre el árbol y el historial. **Hacerlo público** es otra decisión de Juan, con otra búsqueda de fugas sobre el historial |
| **F1a-0 · listas** | Scripts que generan `exposed-products` y `trusted-exploit-authors` con sus criterios escritos; **PR de revisión de Juan** (P-10). Desde entonces, cada cambio de las listas va por PR | PR aprobado y fusionado **antes** de cualquier fixture de nginx2root (R7). Necesita el repo (G-13) |
| **F1a · núcleo sin desplegar** | Modelo de datos y migraciones; `config/sources.yaml` con uso comercial y aislamiento (ADR-020); reglas A/B/C con impacto y carga inicial; colectores de cvelistV5, CISA KEV, nomi-sec, búsqueda de GitHub y nginx.org; **feed completo y de alertas**, con índice paginado y páginas selladas (ADR-019); firma; API; reconstrucción de nginx2root | Pruebas de carga inicial = 0 alertas, DoS ≠ B, ruido, fallo de fuente, monotonía, **CVE fuera de listas en `all` antes de 10 min**, fuente excluida fuera del feed y reconstrucción de nginx2root (B como tarde a las 16:18Z) en verde; consultas de métricas en verde contra el esquema. **Al cerrar: búsqueda de fugas sobre todo el historial y, si Juan lo confirma, el repo pasa a público y se aplica la protección de `main`** (J-7) |
| **F1b · resto del núcleo y en vivo** | El resto de fuentes (EPSS, GHSA, OSV, NVD, Metasploit, Exploit-DB, nuclei, fabricantes y CERT), cada una con su carga inicial; front (5 pantallas, con métricas); despliegue por OIDC (requiere el gate); 72 h en vivo | 72 h sin UNKNOWN no explicados; el portal muestra nginx2root (reconstrucción) con su línea de tiempo |
| **F2 · IA** | Agente, redacción, verificador de citas, topes, conjunto de evaluación en CI, expediente en el portal | Conjunto de evaluación en verde, incluidos la inyección y el DoS |
| **F3 · vigilancia** | Latido, reglas de Sentinel, `SentinelHealth`, **vigilante externo en GitHub Actions**, alerta de presupuesto | Se para `ingest` → llega el incidente; se corta el Tunnel → falla el vigilante externo |
| **F4 · publicación** | Resumen; consumidor de ejemplo para Teams probado contra un receptor local (P-8); cola de aprobación; `/v1/social.atom`; adaptador de la herramienta de redes (ADR-017) | Un post aprobado sale en el Atom y la herramienta lo publica en X, Bluesky y LinkedIn; el consumidor de Teams pasa contra el receptor local |
| **F4b · donaciones** (ADR-021) | Recepción de donaciones en Bitcoin sin custodia (Lightning y on-chain, con una dirección nueva por donación); lectura de lo recibido sin datos del donante; página de reconocimiento; enlace «apoya el proyecto» en el resumen y en los posts. Todo detrás del interruptor `donations.enabled` (por defecto `false`) | Pruebas en testnet o signet; con el interruptor apagado no aparece ningún enlace ni dato de donaciones. **Se activa al cerrar la fase**, tras la revisión legal de Juan |
| **F5 · arquitectura** | Paquete completo con las versiones de ATLAS y ATT&CK fijadas | Test de IDs en verde y revisión externa |

---

## 16. Verificación de punta a punta

1. `uv run pytest` con los snapshots.
2. Feed validado con JSON Schema y OSV; firma comprobada con `openssl`.
3. CI: tests, evaluación, IDs de arquitectura y consultas de métricas.
4. Despliegue por Actions con OIDC. Comprobaciones:
   - `curl` del feed a través de Cloudflare;
   - `/admin` sin sesión devuelve 302;
   - el origen directo no responde.
5. En vivo: 72 h, latido en Sentinel, alerta provocada y vigilante externo provocado.

---

## Requisitos de plataforma (gate; los ejecuta el programa de la plataforma, no esta sesión)

| # | Requisito |
|---|---|
| G-1 | RG propio por entorno, Sweden Central. El nombre va en las variables del pipeline (regla 8) |
| G-2 | Identidad del pipeline con credencial federada OIDC (repo, rama `main`, entorno `prod`). **RBAC solo sobre el RG** (R9, ADR-014): Contributor + **Role Based Access Control Administrator con condición** que solo permite asignar o quitar los roles concretos que necesitan las identidades del RG (Key Vault Crypto User, Key Vault Secrets User, AcrPull si aplica, Cognitive Services User, Monitoring Metrics Publisher), y solo a principales de tipo `ServicePrincipal` |
| G-3 | Documentar la brecha de los permisos heredados (D3) en un ADR |
| G-4 | VNet propia (subredes de ACA, de PostgreSQL delegada y de endpoints privados) y zonas DNS privadas |
| G-5 | Cumplir las políticas aplicables: secretos de KV **con fecha de caducidad** y rotación; ingesta del latido por DCR. Si alguna no se puede cumplir, se documenta el motivo (no se pide excepción) |
| G-6 | Despliegue de prueba de Haiku 5.5 y Sonnet 5.5 (GlobalStandard, Sweden Central) con identidad gestionada; confirma la disponibilidad en esta suscripción |
| G-7 | DCR y tabla `VsHeartbeat_CL` en el workspace de Sentinel; rol de publicación para la identidad de los jobs; 3 reglas programadas |
| G-8 | `SentinelHealth` y la alerta del vigilante interno con su grupo de acciones |
| G-9 | Alerta de presupuesto a 80 € sobre el RG. Se define sobre el coste real del RG, de modo que sigue valiendo igual tras pasar a pago por uso (ADR-015) |
| G-10 | Token de Cloudflare de alcance mínimo para el pipeline, guardado en los secrets de GitHub |
| G-11 | Tunnel, DNS y app de Access de `/admin` («solo Juan», con Entra) |
| G-12 | Comprobar el plan de Workers |
| G-13 | Repo público en el GitHub personal, con reglas de protección. R1 cerrado; lo crea Juan |
| G-14 | **Recordatorio en septiembre de 2027** del cambio de facturación de la suscripción (ADR-015), con margen para revisar costes. La fecha exacta y las condiciones, solo en `local/`. G-9 sigue valiendo con pago por uso |
| G-19 | (F4, ADR-017) Clave de API de la herramienta de redes en el Key Vault del RG, con caducidad; saldo prepago de X y alerta de saldo bajo |
| G-18 | (F4b, ADR-021) Secret en el Key Vault del RG con la lista de direcciones on-chain pregeneradas (o la xpub watch-only), con caducidad y rotación (G-5). Exclusión de logs del endpoint de donación en App Insights y Cloudflare |
| G-17 | Lectura de costes para la transparencia (§9): rol **Cost Management Reader** sobre el RG para la identidad del job diario; token de Cloudflare con lectura de facturación de la cuenta, guardado en el Key Vault del RG |
| G-15 | Bucket de Cloudflare R2 para las páginas selladas y el snapshot (ADR-019); token de R2 **limitado a ese bucket**, guardado en el Key Vault del RG; dominio público del bucket detrás de la misma zona y caché |
| G-16 | Tema de ntfy con control de acceso y su token en los secrets (P-9) |

## Decisiones de Juan (cerradas el 2026-11-25)

| # | Decisión | Dónde |
|---|---|---|
| P-1 | Claude en Foundry con identidad gestionada si G-6 funciona; si no, API de Anthropic con la clave en KV a través de un AI Gateway **nuevo y con autenticación** | ADR-009 (aceptado, condicionado a G-6) |
| P-2 | Agente con Sonnet 5.5 en F2. El conjunto de evaluación lo compara con Haiku 5.5; si Haiku cumple los umbrales, se cambia | ADR-009, §7 |
| P-3 | `vuln.` y `api.vuln.` en la zona actual. Si funciona, puede migrar a marca y dominio propios. Hosts, nombre y marca en configuración | ADR-016, `config/brand.example.yaml`, test de hosts |
| P-4 | Cloudflare Tunnel | ADR-004 (aceptado) |
| P-5 | Token de GitHub: sí. **VulnCheck: sus términos prohíben ofrecer los datos gratis o con licencia abierta → fuera de la v1**, documentado. Vuelve con un permiso por escrito o una licencia | ADR-020, §4 |
| P-6 | Sin integrar las API de las redes: borrador → aprobación → `/v1/social.atom` → herramienta de pago con API permitida (Zernio, aceptada tras descartar Buffer, J-2; alternativa futura Postiz) | ADR-017 (aceptado), §12 |
| P-7 | LinkedIn con el perfil personal | §12 |
| P-8 | El ejemplo de Teams se prueba contra un receptor de webhook local; no se guarda aquí ninguna URL de terceros | §12 |
| P-9 | Correo y ntfy desde los dos vigilantes | §11, G-8, G-16 |
| P-10 | Juan revisa por PR las dos listas antes de F1a; después, cada cambio va por PR. **Cambio de diseño:** feed completo + feed de alertas; las listas solo deciden la urgencia | F1a-0, ADR-019, §3 |
| P-11 | Primero, open core con FSL-1.1-ALv2. **Después, rechazado: todo Apache-2.0**, porque el modelo es de donaciones | ADR-011 (aceptado), ADR-018 (rechazado) |
| P-12 | Python 3.13 + FastAPI; front con **React** (SPA con Vite) en Workers static assets | ADR-005, ADR-006 (aceptados) |
| P-13 | Pago por uso cuando cambie la facturación de la suscripción | ADR-015, G-14 |
| P-14 | El hallazgo del gateway es de la plataforma; solo en `local/` | — |
| P-15 | Ficheros privados en `local/`; resumen público en la bitácora | `docs/journey/00` |

**Sostenibilidad: donaciones, no venta** (decisión de Juan, 2026-11-25).
- El feed es siempre gratis e igual para todos.
- Quien dona recibe reconocimiento (README o una página), nunca datos antes ni mejores.
- Las donaciones son solo en Bitcoin (Lightning y on-chain) y las recibe Juan como persona física
  (ADR-021).
- Las obligaciones fiscales son de Juan y la revisión legal previa a activarlas queda fuera de este
  repo.

## Pendiente de Juan

| # | Qué | Para qué |
|---|---|---|
| J-2 | **Cerrada**: ADR-017 aceptado con **Zernio** el 2026-11-25 (Buffer descartado por la 4.2(n)) | F4 |
| J-3 | **Cerrada**: VulnCheck sigue fuera (cláusula comprobada también por la sesión directora) | ADR-020 |
| J-6 | **Cerrada**: ADR-021 aceptado | F4b |
| J-7 | **Repo público al cerrar la F1a**, tras una búsqueda de fugas sobre todo el historial; Juan lo confirma en ese momento | Fin de F1a |
| J-8 | **Cerrada: sin GitHub Pro.** Regla 9 de `CLAUDE.md` (sin push a `main`; fusiona Juan) + hook `pre-push` local (`.githooks/`). Al hacerlo público se aplica la protección de rama | `CLAUDE.md`, `.githooks/` |
