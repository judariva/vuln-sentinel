---
adr: "0017"
titulo: Publicación en redes con feed Atom y una herramienta de pago con API permitida
estado: aceptado
fecha: 2026-11-25
afecta: [CMP-002, CMP-005, CMP-015]
sustituye: null
---

Aceptado por Juan el 2026-11-25 (J-2): Zernio.

## Contexto

P-6: no se integran las API de las redes una a una. vuln-sentinel genera el borrador, Juan lo
aprueba y el post aprobado se publica como feed Atom (`/v1/social.atom`). Una herramienta existente
lo reparte a X, Bluesky y LinkedIn (perfil personal, P-7). Topes: solo A y B, como mucho 3 posts al
día por canal (~270 posts/mes).

**Buffer, descartado (J-2).** Sus API Terms (4.2 n, «Last updated: August 5, 2026») prohíben «cause
or permit automated queries on the API», que es justo este uso.

Requisitos de Juan (J-2):
- herramienta de pago;
- cubre X, el perfil personal de LinkedIn y Bluesky;
- sus términos permiten **expresamente** publicar por API, con la cita literal verificada;
- sin cláusulas contra la automatización;
- hasta ~20 €/mes;
- el total del producto, por debajo de los 100 € de D6.

## Decisión

1. **Fuente canónica: `/v1/social.atom`**, firmado como el resto del feed. Solo contiene posts
   aprobados.
2. **Herramienta: Zernio** (antes Late; getlate.dev redirige a zernio.com). Adaptador
   de una llamada detrás de la interfaz `SocialPublisher`, invocado al aprobar cada post.
3. **El post de X va sin URL** por defecto (0,015 USD frente a 0,20 USD con enlace). El enlace va
   en el perfil o en una respuesta.

## Comprobación de Zernio (2026-11-25)

Las citas en negrita las comprobé yo con `curl` sobre la página original.

| Requisito | Resultado | Cita y fuente |
|---|---|---|
| Publicar por API | **Sí.** Es el objeto del servicio | «Zernio **provides APIs and a dashboard for publishing and scheduling** social media content…» ([ToS](https://zernio.com/tos), «**Last updated: November 7, 2026**») |
| Cláusula contra la automatización | **Ninguna.** Busqué automat, robot, bot, script, scrap y crawl en el texto: solo aparecen la recarga automática del saldo y la aceptación automática del DPA. El uso de la API se limita por cuotas: «Your use of our API is subject to rate limits and usage quotas … **Abuse of the API may result in immediate suspension** of your account» | [ToS](https://zernio.com/tos) |
| X, perfil personal de LinkedIn y Bluesky | Sí. LinkedIn: «Publish … posts to LinkedIn **personal profiles and organization pages with the Zernio** API» | [LinkedIn](https://docs.zernio.com/platforms/linkedin), [Bluesky](https://docs.zernio.com/platforms/bluesky), [X](https://docs.zernio.com/platforms/twitter) |
| X sin credenciales propias | Sí: se conecta sin claves propias y X se paga desde un saldo prepago, al precio de X. «A post costs **$0.015 ($0.20 with a link). At a $0 balance, p**osting to X returns insufficient_balance». «We pass through their exact rates with **zero markup**» | [X](https://docs.zernio.com/platforms/twitter), [pricing](https://zernio.com/pricing) |
| Precio | «Every feature included, no plans, no seats … **1–2 Free 3–10 $6/account/mo**»: 3 canales ≈ **6 USD/mes** más el saldo de X (90 posts sin URL ≈ 1,35 USD/mes; con URL, 18 USD) | [pricing](https://zernio.com/pricing) |
| Proyecto sin ánimo de lucro | No hay ninguna restricción. El titular es ZERNIO SOFTWARE SL (España) | [ToS](https://zernio.com/tos) |

**Matiz que decidió Juan (aceptado).** Los términos de Zernio permiten publicar por API («provides APIs … for
publishing and scheduling») pero **no usan literalmente la palabra «automatizado»**. La única
candidata que la usa es Upload-Post, aunque añade una cláusula restrictiva acotada (ver abajo).

**Riesgos.**
- Cambio de marca reciente (Late → Zernio).
- Su cláusula 8 permite suspender la cuenta «for any reason whatsoever»: el Atom sigue siendo la
  fuente canónica y el adaptador se puede cambiar.
- Hay que mantener saldo para X.

## Comparativa (2026-11-25)

| Herramienta | Redes (LinkedIn personal) | Precio para 3 canales | X | Cláusula contra la automatización | Veredicto |
|---|---|---|---|---|---|
| **Zernio** | Sí | ≈ 6 USD/mes + X al precio de X | Sin credenciales propias; saldo prepago | Ninguna | **Recomendada** |
| Upload-Post (TONVI TECH SL) | Sí ([doc](https://docs.upload-post.com/api/upload-text)) | Basic 24 USD/mes (16 en pago anual); URL en X: +19 USD/mes | Incluido | 3.1 permite «automated posting, scheduling, bulk uploads … and API integrations». 2.2 prohíbe «automated scripts, bots … **beyond normal API usage**», con «immediate termination … without refund» ([ToS](https://www.upload-post.com/terms-of-use/), 02-10-2026) | Segunda opción |
| Outstand | Probable (SIN VERIFICAR) | 19 USD/mes + X aparte | **Credenciales propias de X obligatorias** ([doc](https://www.outstand.so/docs/getting-started)) | Ninguna | Válida si se aceptan claves de X propias |
| Typefully | Sí | Plan de pago (SIN VERIFICAR) | SIN VERIFICAR | «processes that run or are activated while you are not logged into the Services» ([ToS](https://support.typefully.com/en/articles/8718440-terms-of-service)) | Descartada: choca con un job de servidor |
| Publer | Sí (SIN VERIFICAR) | ≈ 24 USD/mes (API solo en Business) | Incluido en el plan de pago | Prohíbe robots «through any means not purposely made available» ([ToS](https://publer.com/terms)): ambigua | Descartada: riesgo y precio |
| Postiz Cloud | SIN VERIFICAR | 29 USD/mes | Incluido | Ninguna aplicable | Descartada por precio |
| Ayrshare | Sí | 149 USD/mes | Credenciales propias de X | Ninguna | Descartada por precio |
| Blotato | — | 29 USD/mes | SIN VERIFICAR | Ninguna | Descartada por precio |
| SocialBee | — | — | — | No tiene API pública | Descartada |
| Buffer | Sí | 0–15 USD/mes | Incluido | **4.2(n)** | **Descartada (J-2)** |

**Alternativa futura: Postiz autoalojado** (AGPL-3.0, [repo](https://github.com/gitroomhq/postiz-app)).
Sin dependencia de un proveedor, con RSS nativo que puede leer `/v1/social.atom` y con API. Hoy no
compensa: su compose levanta 9 servicios y exige apps propias en X y LinkedIn.

## Consecuencias

- Coste: ≈ 6 USD/mes más 1,35 USD/mes de X sin URL. Cabe en D6 y en el tope de ~20 €/mes de J-2.
- Lock-in bajo: el Atom es la fuente canónica y el adaptador es una sola llamada.
- El job de publicación necesita la clave de API de Zernio en Key Vault (G-19) y una alerta de saldo
  bajo de X.

## Evidencia

Verificado por la sesión principal con `curl` el 2026-11-25:
- https://zernio.com/tos
- https://zernio.com/pricing
- https://docs.zernio.com/platforms/twitter
- https://docs.zernio.com/platforms/linkedin
- https://docs.zernio.com/platforms/bluesky

El resto de las URL de la tabla vienen del informe de investigación del mismo día.
