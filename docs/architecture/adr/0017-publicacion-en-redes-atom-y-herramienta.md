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

## Comprobación de Buffer (2026-11-25)

Hecha por la sesión de trabajo. Las citas en negrita las comprobé yo con `curl` sobre la página
original.

| Condición | Resultado | Evidencia |
|---|---|---|
| ¿Uso permitido para este proyecto? | **Sí, con una salvedad.** No hay restricción a uso personal ni no comercial en el plan Free, y la API está en todos los planes. **Salvedad:** los API Terms (4.2 n) prohíben «**cause or permit automated queries on the API**», y el ToU licencia la API para «**internally use the API** in connection with the Service». Eso choca literalmente con el uso previsto, aunque el centro de ayuda presente la API como algo para «agents, scripts, and apps» | [buffer.com/terms](https://buffer.com/terms) (API Terms, «**Last updated: August 5, 2026**»); [centro de ayuda](https://support.buffer.com/articles/what-is-buffers-api-GtIYIQilz5): «**available on every Buffer plan, including the Free plan**» |
| ¿Credenciales propias de X? | **No las pide.** Ningún texto de Buffer las exige ni cobra aparte: «it isn't a social network's own API … we still handle publishing». Ayrshare afirma que X las exige a todos los terceros desde el 31-03-2026; Buffer no lo refleja. Riesgo a vigilar, SIN VERIFICAR | [X en Buffer](https://support.buffer.com/articles/using-xtwitter-with-buffer-nA84XnWtuU); [Ayrshare](https://www.ayrshare.com/docs/dashboard/connect-social-accounts/x-twitter-byo-keys) |
| ¿Posts sin enlace? | Buffer **no acorta por defecto** («By default, links in Buffer are not shortened»), y por API las URL se mantienen completas salvo que se llame a `shortenLink`. Nada indica que añada un enlace a un post que no lo lleva (SIN VERIFICAR como ausencia). Si X cobra distinto a Buffer por posts con URL: SIN VERIFICAR | [enlaces](https://support.buffer.com/articles/shortening-and-unshortening-links-dgev2p41yY); [developers](https://developers.buffer.com/llms-full.txt) |
| Límites del plan Free | 3 canales (justo X, Bluesky y LinkedIn). Cola de 10 posts programados por canal, que no es un límite diario. API: 1 cliente, 150 peticiones / 15 min, 600 / 24 h y 1.000 por canal cada 30 días. Si `shareNow` cuenta para la cola de 10: SIN VERIFICAR. Hay una contradicción: `pricing.md` dice 5 claves en todos los planes y la documentación, 1 en Free | [plan Free](https://buffer.com/pricing/free); [límites de la API](https://developers.buffer.com/guides/api-limits.html) |
| LinkedIn personal y Bluesky | Incluidos | [plan Free](https://buffer.com/pricing/free); [LinkedIn](https://support.buffer.com/articles/using-linkedin-with-buffer-K7tRkGD3mH); [Bluesky](https://support.buffer.com/articles/using-bluesky-with-buffer-7f6OcRnzIO) |
| Límite de X a través de Buffer | 50 posts/24 h en cuentas sin verificar; X no admite posts duplicados | [límites diarios](https://support.buffer.com/articles/daily-posting-limits-kJ0JtpsdvD) |

**Recomendación a Juan:** aceptar Buffer **condicionado a una confirmación por escrito** del soporte
de desarrolladores de Buffer de que el uso previsto no incumple la 4.2(n). El uso previsto es
publicar hasta 3 posts/día por canal en cuentas propias, desde un job, mediante `createPost` en el
momento de una aprobación humana.
- Mientras tanto, `/v1/social.atom` sigue siendo la fuente canónica y el adaptador queda apagado.
- Si Buffer no lo confirma, se pasa a Postiz autoalojado o a publicar a mano desde el Atom.
- El ToU dice que el servicio está «intended for visitors located within the United States»
  (cláusula 17.7). Es un punto más para la revisión legal de Juan.

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
