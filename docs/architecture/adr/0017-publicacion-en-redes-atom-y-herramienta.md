---
adr: "0017"
titulo: Publicación en redes con feed Atom y una herramienta existente
estado: propuesto
fecha: 2026-11-25
afecta: [CMP-002, CMP-005, CMP-015]
sustituye: null
---

## Contexto

P-6: no se integran las API de las redes una a una. vuln-sentinel genera el borrador, Juan lo
aprueba y el post aprobado se publica como feed Atom (`/v1/social.atom`). Una herramienta existente
lo reparte a X, Bluesky y LinkedIn (perfil personal, P-7). Topes: solo A y B, como mucho 3 posts al
día por canal.

## Decisión

1. **Fuente canónica: `/v1/social.atom`**, firmado como el resto del feed. Solo contiene posts
   aprobados.
2. **Adaptador de una llamada a Buffer** (API GraphQL, `createPost`) en el momento de la aprobación.
   Plan Free para empezar; Essentials (5 USD por canal y mes, 15 USD/mes con 3 canales) si se queda
   corto. El adaptador está detrás de una interfaz `SocialPublisher` y se puede cambiar.
3. **El post de X va sin URL** (el enlace, en la primera respuesta o en el perfil): X cobra
   0,015 USD por post y 0,20 USD si lleva URL.

**Condiciones para pasar a aceptado** (SIN VERIFICAR el 2026-11-25):
- los términos de Buffer permiten el uso comercial en el plan elegido;
- Buffer no obliga a traer credenciales propias de la API de X (Ayrshare afirma que X lo exige a
  terceros desde el 31-03-2026; X no lo ha confirmado);
- el límite de 10 posts programados por canal del plan Free no afecta a la publicación inmediata.

Si alguna falla, se pasa a la alternativa.

## Comparativa (2026-11-25)

| Herramienta | Redes | Entrada | Plan mínimo | X | Veredicto |
|---|---|---|---|---|---|
| Buffer | X, Bluesky, Mastodon, Threads, LinkedIn personal ([pricing](https://buffer.com/pricing)) | API GraphQL ([developers](https://developers.buffer.com)); RSS solo vía Zapier o IFTTT | Free 0 USD; Essentials 15 USD/mes (3 canales) | Coste incluido o no: SIN VERIFICAR | **Recomendada** |
| Typefully | X, LinkedIn, Bluesky, Mastodon, Threads ([API](https://typefully.com/docs/api)) | API de borradores | Creator ~8 USD/mes (dato de un tercero, SIN VERIFICAR) | SIN VERIFICAR; la API se describe como «para automatizaciones personales» | Equivalente; pendiente de aclarar términos |
| Postiz (autoalojado) | X, LinkedIn, Bluesky, Mastodon, Threads ([pricing](https://postiz.com/pricing)) | RSS nativo y API | 0 € de licencia (AGPL-3.0, [repo](https://github.com/gitroomhq/postiz-app)) + servidor | App propia de X y pago por uso a X ([doc](https://docs.postiz.com/providers/x-twitter)) | **Alternativa** si se prioriza el control |
| Ayrshare | Más de 14 redes | API | 149 USD/mes | Credenciales propias obligatorias ([doc](https://www.ayrshare.com/docs/dashboard/connect-social-accounts/x-twitter-byo-keys)) | Descartada: fuera de presupuesto |
| Make | Bluesky, LinkedIn personal | Escenarios | Free / Core | **Sin X** ([aviso](https://help.make.com/x-formerly-twitter-app-integration-discontinued)) | Descartada |

## Alternativas descartadas

- Integrar las API de X, LinkedIn y Bluesky directamente: lo excluye P-6 (mantenimiento, cambios de
  API, revisión de apps).
- Postiz autoalojado en la plataforma: su compose oficial levanta 9 servicios (Postgres, Redis,
  Temporal con Elasticsearch…). Cuesta más de operar que el propio producto. Queda como alternativa
  fuera de la plataforma.

## Consecuencias

- Lock-in bajo: el Atom es la fuente canónica y el adaptador es una sola llamada.
- Coste estimado: 0–15 USD/mes de Buffer más 0–1,35 USD/mes de X si hiciera falta pagarlo aparte
  (90 posts sin URL).
- Si X exige credenciales propias, el coste de X es el mismo con cualquier herramienta.

## Evidencia

Las URL de la tabla, consultadas el 2026-11-25. Precio de X: https://docs.x.com/x-api/getting-started/pricing
