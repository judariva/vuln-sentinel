---
adr: "0019"
titulo: Feed completo de CVE y feed de alertas
estado: aceptado
fecha: 2026-11-25
afecta: [CMP-002, CMP-003, CMP-005, CMP-011, CMP-016]
sustituye: null
---

## Contexto

El feed solo publicaba alertas activas. Una CVE nueva de un producto fuera de las categorías
expuestas nunca llegaba al consumidor, aunque la tuviera en su inventario (decisión de Juan sobre
P-10).

## Decisión

Dos feeds sobre el mismo modelo:
- **`/v1/feed/all/…`**: todas las CVE nuevas o cambiadas, normalizadas en OSV, con productos y
  rangos y con su nivel (`A`, `B`, `C` o `none`). Se publican a los ~5 min de verlas.
- **`/v1/feed/alerts/…`**: solo A, B y C. Es lo que despierta a alguien.

Las listas `exposed-products` y `trusted-exploit-authors` **solo deciden la urgencia**, no qué entra
en el feed.

### Volumen (medido el 2026-11-25)

- **CVE nuevas al día:** media 587, mediana 521, pico 2.077.
- **CVE modificadas al día:** media 2.140, pico 6.426.

Medido en `deltaLog.json` de cvelistV5, del 26-10 al 25-11-2026
([fuente](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json)). En 2026
van más de 100.000 CVE a 13-11 ([The Register](https://www.theregister.com/a/5309882)).

Un registro OSV ocupa entre 2,6 y 61,6 KB; la mediana estimada es de ~5 KB (~1,6 KB en gzip). Fuente:
`api.osv.dev/v1/vulns/{id}` para 4 casos reales.

| Formato | Día medio | Día pico | 30 días |
|---|---|---|---|
| Índice de cambios (~150 B por entrada) | ~0,4 MB | ~1,3 MB | ~12 MB |
| Registros completos | ~13 MB | ~45 MB | ~400 MB |

### Diseño

1. **`changes` lleva solo el índice**: `id`, `modified`, `level`, `type` y `sha256`. Cada registro se
   sirve en `/v1/vulns/{id}.json` con un ETag igual a su hash.
2. **Cursor opaco** (`since=<modified>,<id>`), con orden estable y un límite de 1.000 entradas por
   página (máximo 5.000).
3. **Páginas selladas por hora** (`/v1/feed/all/changes/2026-11-25T15.json`), inmutables y con
   `Cache-Control: public, max-age=31536000, immutable`. Solo la página en curso («head») lleva un
   TTL de 60 s.
4. **Retención de `changes`: 30 días.** Un cursor más antiguo recibe un `410` con el enlace al
   snapshot.
5. **Snapshot diario completo** (zip por ecosistema, como el `all.zip` de OSV) en **Cloudflare R2**
   (CMP-016). R2 no cobra la salida de datos y su plan gratuito incluye 10 GB. Las páginas selladas
   también se escriben en R2. La API solo sirve la página «head» y los registros individuales.
6. Cada documento lleva su firma JWS detached, como en ADR-0008. En el snapshot se firma el
   manifiesto con los hashes, no cada fichero.

## Alternativas descartadas

- Meter los registros completos en `changes`: hasta 45 MB al día y páginas que no se pueden cachear.
- Publicar solo las alertas: el consumidor pierde CVE de su inventario (el problema de partida).

## Consecuencias

- La base de datos guarda todas las CVE, no solo las candidatas. Con unos 220.000 registros al año,
  32 GB sobran durante años.
- El job de publicación escribe en R2. Necesita un token de R2 limitado al bucket, guardado en Key
  Vault (G-15).
- Nueva métrica: CVE en el feed completo frente a CVE alertadas.
- Nueva prueba: una CVE de un producto que no está en ninguna lista aparece en `all` con
  `level: none` antes de 10 minutos.

## Evidencia

Medidas del 2026-11-25 citadas arriba. Tamaño máximo de objeto en la caché de Cloudflare: SIN
VERIFICAR (con páginas de ~150 KB no debería importar).
