---
entrada: "00"
fecha: 2026-11-25
adr: ["0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008", "0009", "0010", "0011", "0012", "0013", "0014", "0015"]
---

# 00 · Origen y decisiones

## Por qué existe

Con la IA se publican más vulnerabilidades, y más rápido. La mayoría no importan. Las pocas que
sí importan tienen que verse **el mismo día**: las explotadas, las que tienen exploit público y las
de productos expuestos a Internet de uso masivo. Y tienen que llegar a las herramientas de cada
organización, que deciden dentro de su propio entorno si les afectan. Hoy esa señal suele llegar
tarde.

vuln-sentinel lee fuentes públicas y clasifica por peligro, no por CVSS. Publica un feed firmado
que cualquier herramienta puede cruzar con su inventario sin IA. Además es un caso de estudio
público: cada decisión tiene su ADR y cada control, su amenaza y su prueba.

## Decisiones de partida

| # | Decisión |
|---|---|
| D1 | Producto de Juan, open source, en un repo público de su GitHub personal (Apache-2.0) |
| D2 | Solo GitHub Actions despliega: OIDC en Azure, token mínimo en Cloudflare. La sesión local solo lee y valida |
| D3 | En Azure, un grupo de recursos propio. El pipeline solo tiene permisos sobre él; la herencia de permisos superiores es una brecha conocida y documentada |
| D4 | En Cloudflare, la administración va detrás de Access |
| D5 | El modelo de IA se elige con evidencia; la preferencia es Claude en Microsoft Foundry |
| D6 | Presupuesto máximo de 100 €/mes en total |
| D7 | Los cambios en la plataforma se ejecutan como un gate aparte, con aprobación de Juan |
| D8 | Publicación: feed firmado, resumen diario, Teams como consumidor de ejemplo, X y LinkedIn con aprobación humana |
| D9 | El núcleo corre en Azure (Container Apps y una base de datos gestionada); Cloudflare es el borde |
| D10 | El portal es un consumidor más de la API pública; la administración va detrás de Access |
| D11 | Las métricas salen de la base de datos del producto; la telemetría solo dice si está vivo |
| D12 | La arquitectura se documenta como datos con IDs estables, analizables por terceros |
| D13 | Un solo agente de IA, el investigador, para los candidatos sin explotación confirmada. Redactar es una llamada simple |
| D14 | El agente solo lee, sobre dominios permitidos y con topes. Cada afirmación lleva su cita verificada. Solo puede subir el nivel. Un conjunto de evaluación lo mide en CI |
| D15 | El chat sobre el feed queda fuera de la v1 |
| D16 | Esta bitácora: qué se decidió, qué falló y las métricas de cada fase, sin datos privados |

Requisito del modelo de datos: cada hecho guarda cuándo dice la fuente que ocurrió
(`source_published_at`) y cuándo lo vio el monitor (`observed_at`). Sin las dos no se puede medir el
tiempo de detección.

## Qué cambió tras la revisión del plan

La primera versión del plan pasó una revisión externa. Salió «aprobado con cambios»:

| # | Qué cambió |
|---|---|
| R1 | Lo que describe la plataforma subyacente no va al repo público, aunque no lleve identificadores |
| R2 | **Carga inicial sin alertas.** La primera ejecución de cada fuente es su referencia; solo alerta lo reciente o lo que cambia después. Sin esto, el primer arranque habría dado miles de alertas (ADR-0012) |
| R3 | **B exige impacto mínimo**: RCE, bypass de autenticación o lectura/escritura arbitraria. Un exploit de solo DoS no es urgente (ADR-0013) |
| R4 | KEV publica la fecha, no la hora. La «ventaja sobre KEV» se mide con la hora de observación, con ±15 min |
| R5 | Se añade la evaluación de reglas por CVE para poder calcular el embudo. Las consultas de las métricas se escriben antes de construir |
| R6 | La cronología de nginx2root separa hechos, inferencias y desconocidos. Lo defendible es B como tarde a las 16:18Z del 18/11. La prueba con snapshots es una **reconstrucción**; la real es el siguiente caso en vivo |
| R7 | La lista de autores de exploits de confianza se genera con un criterio escrito y se commitea antes del caso de prueba, para que la prueba no se demuestre a sí misma |
| R8 | Un vigilante externo (GitHub Actions) comprueba el feed desde fuera, independiente de la nube del producto |
| R9 | Mínimo privilegio real en el pipeline: puede asignar roles, pero solo los concretos y solo a identidades de servicio (ADR-0014) |
| R10 | La primera fase se divide en F1a (núcleo sin desplegar) y F1b (resto de fuentes, portal y en vivo) |

Además: se fijan las versiones de MITRE ATLAS (5.6.0) y ATT&CK (v20.1), y se citan con URL todos los
precios.

## Cómo se sostiene: donaciones, no venta

Durante la planificación se valoró un modelo open core: el contrato abierto y el motor con una
licencia que impidiera ofrecerlo como servicio (ADR-0018). Se rechazó. El feed es siempre gratis e
igual para todos, y todo el proyecto es Apache-2.0 (ADR-0011). Se sostiene con donaciones en
Bitcoin, sin custodia (ADR-0021). Quien dona recibe reconocimiento, nunca datos antes ni mejores.
Una pantalla pública muestra el coste real del proyecto frente a lo recibido.

Siguiente entrada: `F0-arranque.md`.
