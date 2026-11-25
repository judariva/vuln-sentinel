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
| ADR-005 | Front en **Workers static assets** | Gratis en estáticos ([doc](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/)); es un consumidor de la API (D10) |
| ADR-006 | **Python 3.13** | Rangos de versión (`univers`, purl), OSV y CSAF |
| ADR-007 | Feed **OSV 1.9.x extendido** | Cruce directo por purl ([spec 1.9.2](https://ossf.github.io/osv-schema/)). CSAF VEX como exportación posterior (CSAF 2.1 aún es CS01) |
| ADR-008 | Firma **ES256 (JWS detached)** con clave no exportable en Key Vault | La clave no sale de KV. Ed25519 en KV Standard: **SIN VERIFICAR** |
| ADR-009 | IA: **Claude en Foundry con identidad gestionada** (depende de G-6) | Preferencia D5, sin secretos. Respaldo: API de Anthropic con clave en KV, a través de un AI Gateway **propio y con autenticación** |
| ADR-010 | Agente: **bucle propio con tool use** en un ACA Job | Agent Service no admite Claude; portable; OTel |
| ADR-011 | Licencia **Apache-2.0**; `NOTICE` con atribuciones de datos | GHSA CC-BY 4.0, EPSS, NVD, CVE ToU, VulnCheck |
| ADR-012 | **Carga inicial de referencia** por fuente, sin alertas (R2) | Evitar la avalancha del primer arranque y la de cada fuente nueva |
| ADR-013 | **B exige impacto mínimo** (R3) | Un exploit de DoS o de fuga de versión no es urgente |
| ADR-014 | Pipeline con **RBAC Administrator con condición** (R9) | Que el pipeline no pueda darse a sí mismo cualquier rol |
| ADR-015 | **Continuidad de la suscripción**: al cambiar su modelo de facturación pasa a pago por uso, a cargo de Juan (P-13) | El producto es 24/7; el coste ya está dimensionado para pago por uso (§14) |

---

## 3. Contrato del feed (lo más importante)

Base: **OSV 1.9.x**. Una alerta equivale a un registro OSV. Las extensiones van en
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
      "kev":   {"cisa": false, "vulncheck": false, "observed_at": "…"},
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
- Endpoints: `/v1/feed/latest.json`, `/v1/feed/changes?since=`, `/v1/alerts/{id}`,
  `/v1/digest/{fecha}.json`. Cada uno va acompañado de su `.jws`.
- Clave pública: `/.well-known/vuln-sentinel/keys.json` (JWKS con `kid` y rotación).
- Versión del contrato: cabecera `X-VS-Schema: 1.0.0` y `schema/feed-1.0.0.json` en el repo. Un
  cambio incompatible sube la versión mayor y la anterior se sirve 90 días más.
- Firma: JWS detached (RFC 7797) sobre los bytes exactos. Se verifica con `openssl` o con una
  librería JOSE; `examples/verify/` trae un ejemplo.

---

## 4. Fuentes (comprobadas el 2026-11-25)

| Fuente | Aporta | Consumo y frecuencia | Límites y términos | Estado |
|---|---|---|---|---|
| [cvelistV5](https://github.com/CVEProject/cvelistV5) | CVE nuevos y cambios; ADP de CISA (SSVC); PURL (5.2) | Commits de GitHub cada 5 min; zip delta horario como respaldo | GitHub 5.000/h con token; aviso de los CVE ToU | Activo |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Explotación (A). **`dateAdded` es una fecha, sin hora** (R4) | JSON cada 15 min, diff por `cveID` | [CC0](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) | Activo (catálogo 2026.11.24, 1.795) |
| [VulnCheck KEV](https://docs.vulncheck.com/community/vulncheck-kev/introduction) | Explotación (A) | API v3 cada 15 min | Cuenta community; [atribución visible](https://docs.vulncheck.com/community/vulncheck-kev/attribution) | Activo |
| [Vulnrichment](https://github.com/cisagov/vulnrichment) | SSVC | A través del ADP de cvelistV5; el repo como respaldo | CC0 | Activo |
| [EPSS](https://www.first.org/epss/data) | Probabilidad y salto | CSV diario después de las 13:45 UTC | Piden atribución | Modelo v4 |
| [GHSA](https://docs.github.com/en/rest/security-advisories/global-advisories) | Rangos de ecosistemas | `?modified=` cada 15 min | CC-BY 4.0 | Activo |
| [OSV.dev](https://google.github.io/osv.dev/data/) | Rangos | `modified_id.csv` | Licencia por fuente: **se excluyen las NC-ND** | Activo |
| [NVD 2.0](https://nvd.nist.gov/developers/start-here) | CPE/CVSS (solo KEV y software crítico) | Bajo demanda | 50/30 s con key; aviso | [Recortado desde el 15-04-2026](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth) |
| Metasploit | Exploit (E1); el **tipo** de módulo distingue exploit, auxiliary y DoS | `modules_metadata_base.json`, diario | BSD-3 (SIN VERIFICAR) | Activo |
| [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) | Exploit (E2); el **tipo** (`dos`, `remote`, `webapps`, `local`) | `files_exploits.csv`, diario | GPL-2.0+ | Activo |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | Detectable (señal, no exploit) | `cves.json` cada hora | MIT | Activo |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Candidatos a PoC | JSON por CVE, cada hora | CC0; «Be careful Malware» | Activo |
| [Búsqueda de GitHub](https://docs.github.com/en/rest/search/search) | PoC recientes de candidatos | Solo candidatos B/C | 30/min con token | — |
| Fabricantes y CERT | Rangos, fix, «explotado» | RSS/CSAF (nginx.org, Fortinet, Palo Alto, Cisco, MSRC, Red Hat, Siemens, CERT-EU, INCIBE-CERT, CISA) | Varía | F5: sin CSAF; varios **SIN VERIFICAR** |
| OpenCVE | — | **Descartado** | Free 100/h; BSL | — |

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
  - `kev.cisa` o `kev.vulncheck`;
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

Todo hecho lleva `source_published_at` y `observed_at`. El borrador de DDL y las consultas de las
métricas están en `docs/metrics/` (R5).

| Tabla | Campos clave |
|---|---|
| `source` | `name` (PK), `baseline_completed_at`, `freshness_threshold` |
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

---

## 9. Métricas v1 (D11)

Se calculan sobre la BD y se precalculan cada día en `metric_daily`. Las consultas están en
`docs/metrics/queries.sql`.

| Grupo | Métrica | Definición |
|---|---|---|
| Qué detecta | Embudo | Ingeridas (`vulnerability`) → elegibles (`rule_evaluation.eligible`) → candidatas (expuestas con `impact_class ≠ other`) → A, B o C (`result_level`), por día |
| | Reparto | Por CWE agrupado, por categoría y por fabricante; cambios por tipo |
| Qué tan rápido | Tiempo de detección | `alert.first_published_at − min(source_published_at)` de la CVE, p50 y p95 por nivel |
| | **Ventaja sobre KEV** (R4) | `observed_at` de la señal `kev_cisa` menos la primera alerta B o C de la CVE. **Precisión: ±15 min** (sondeo); `dateAdded` de KEV es solo una fecha y no se usa para restar |
| | Escalado | De C a B o A, frente al `observed_at` de la señal que lo provocó |
| Qué tan bien | Precisión | Según el veredicto |
| | **Fallos** | Altas de KEV (posteriores a la carga inicial) en productos expuestos sin alerta B o A previa |
| | IA | Confirmaciones e intentos de bajar el nivel bloqueados |
| Salud | Fuentes | Estado y antigüedad de cada fuente; latido; coste de IA por día; publicaciones pendientes |

---

## 10. Portal (D10)

| Pantalla | Acceso | Contenido |
|---|---|---|
| Hoy | Público | Alertas del día por nivel, con los cambios |
| Detalle de alerta | Público | Productos y rangos, señales, línea de tiempo con las dos marcas de tiempo, fuentes, expediente de IA |
| Métricas | Público | Catálogo de la sección 9 |
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
  1. lee `/v1/feed/latest.json` a través de Cloudflare;
  2. verifica la firma JWS con la clave pública;
  3. comprueba que `modified` tenga menos de 30 min y que ninguna fuente lleve más de 2 h en UNKNOWN.

  Si algo falla, el workflow falla y GitHub avisa por correo (gratis). Cubre también Cloudflare, el
  Tunnel y la clave. Limitación declarada: los cron de Actions pueden retrasarse varios minutos en
  momentos de carga.
- **Tope de IA en código**: 1,5 USD/día.

---

## 12. Publicación (D8)

- **Feed firmado.** Se regenera en cada ciclo con cambios. TTL de 60 s en Cloudflare y purga por URL
  al publicar.
- **Resumen diario.** A las 07:00 Europe/Madrid, como `/v1/digest/{fecha}.json` y como página del
  portal. Incluye las fuentes en UNKNOWN.
- **Teams, como consumidor de ejemplo** (`examples/teams-consumer/`). Lo ejecuta el consumidor:
  1. lee `changes?since=`;
  2. verifica la firma;
  3. filtra por su inventario;
  4. envía una Adaptive Card 1.2 a su webhook de Workflows
     ([MS Learn](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)).
- **X, LinkedIn y Bluesky, con aprobación.** El post se redacta con Haiku sobre una plantilla fija.
  Solo se publican A y B, como máximo 3 al día por canal.

  | Canal | Condiciones |
  |---|---|
  | X | 0,20 USD por post con URL ([docs.x.com](https://docs.x.com/x-api/getting-started/pricing)) |
  | LinkedIn | Perfil personal, self-serve ([MS Learn](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/share-on-linkedin)) |
  | Bluesky | Gratis |

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
| X (3 posts/día) | ~16 | LinkedIn y Bluesky, 0 |
| GitHub Actions (CI y vigilante externo) | 0 | Repo público |
| **Total** | **≈ 85 €** (peor caso ≈ 98 €) | Cabe en D6 con poco margen |

Palancas:
- agente con Haiku (−30 €);
- 1 post al día en X (−11 €);
- KV sin endpoint privado, que entraría **como ADR** si G-4 se complica, no como atajo.

Alerta de presupuesto a 80 € (G-9).

---

## 15. Fases

| Fase | Contenido | Termina cuando |
|---|---|---|
| **F0 · arranque (local)** | Reglas en `CLAUDE.md`; estructura; CI; licencia y `NOTICE`; plantillas de ADR; ADR-001…014; `architecture.yaml` inicial con su test; `docs/journey/`; `STATE.md`; criterio de `trusted-exploit-authors` (R7); DDL en borrador y consultas de métricas (R5). **Sin push** hasta cerrar R1 | `uv run pytest` y `ruff` en verde en local |
| **F1a · núcleo sin desplegar** | Modelo de datos y migraciones; reglas A/B/C con impacto y carga inicial; script que genera la lista de autores (**commit antes del fixture**); colectores de cvelistV5, KEV (×2), nomi-sec, búsqueda de GitHub y nginx.org; feed OSV firmado; API; reconstrucción de nginx2root | Pruebas de carga inicial = 0 alertas, DoS ≠ B, ruido, fallo de fuente, monotonía y reconstrucción de nginx2root (B como tarde a las 16:18Z) en verde; consultas de métricas en verde contra el esquema |
| **F1b · resto del núcleo y en vivo** | El resto de fuentes (EPSS, GHSA, OSV, NVD, Metasploit, Exploit-DB, nuclei, fabricantes y CERT), cada una con su carga inicial; front (5 pantallas, con métricas); despliegue por OIDC (requiere el gate); 72 h en vivo | 72 h sin UNKNOWN no explicados; el portal muestra nginx2root (reconstrucción) con su línea de tiempo |
| **F2 · IA** | Agente, redacción, verificador de citas, topes, conjunto de evaluación en CI, expediente en el portal | Conjunto de evaluación en verde, incluidos la inyección y el DoS |
| **F3 · vigilancia** | Latido, reglas de Sentinel, `SentinelHealth`, **vigilante externo en GitHub Actions**, alerta de presupuesto | Se para `ingest` → llega el incidente; se corta el Tunnel → falla el vigilante externo |
| **F4 · publicación** | Resumen, consumidor de ejemplo para Teams, X, LinkedIn y Bluesky con aprobación | Un post aprobado se publica en cada canal |
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
| G-14 | Recordatorio antes de la fecha de cambio de facturación de la suscripción (ADR-015), con margen para revisar costes. Fecha y condiciones solo en `local/` |

## Decisiones pendientes de Juan

| # | Decisión | Recomendación |
|---|---|---|
| P-1 | IA en Foundry con identidad gestionada o API de Anthropic con KV y un AI Gateway propio | Foundry si G-6 funciona |
| P-2 | Modelo del agente | Sonnet 5.5 en F2; volver a medir |
| P-3 | Nombres de host | `vuln.` y `api.vuln.` |
| P-4 | Tunnel o restricción de IP | Tunnel |
| P-5 | Cuentas: VulnCheck community y token de GitHub sin permisos | Sí |
| P-6 | X (~16 €/mes) y Bluesky | 3 posts/día como máximo en X, más Bluesky |
| P-7 | LinkedIn: perfil o página | Perfil |
| P-8 | Tenant para el ejemplo de Teams | Por decidir |
| P-9 | Destino de los avisos del vigilante | Correo + ntfy |
| P-10 | Revisión de las listas `trusted-exploit-authors` (generada con el criterio de la sección 5.3) y `exposed-products` antes de F1a | Sí, por PR |
| P-11 | Licencia y nombre del repo | Apache-2.0, `vuln-sentinel` |
| P-12 | Stack | Python 3.13 + FastAPI; front con Astro estático |
| P-13 | **Resuelta**: pasa a pago por uso, a cargo de Juan (ADR-015, G-14) | — |
| P-14 | Hallazgo de plataforma anotado en `local/PLATFORM-FINDINGS.md` para el programa de la plataforma | No se toca desde aquí |
| P-15 | **Resuelta**: las decisiones originales y la revisión pasan a `local/` como histórico privado; resumen público en `docs/journey/00-origen-y-decisiones.md` | — |
