# vuln-sentinel

Monitor 24/7 de vulnerabilidades **nuevas y peligrosas**. **Producto real y open source** de Juan,
desplegado en su plataforma: el núcleo en Azure y el borde en Cloudflare. Después servirá como caso
de estudio público de arquitectura y de controles de seguridad de IA. Por eso cada decisión tiene
su ADR y cada control, su amenaza y su prueba.

Español de España. Directo, frases cortas, sin adjetivos comerciales.

Precedencia: mandan las reglas de este fichero. `local/DECISIONS.md` es histórico privado (no se
versiona); el resumen público de las decisiones está en `docs/journey/00-origen-y-decisiones.md`.

## Reglas que no se negocian

1. **Solo información pública.** Aquí no entra ningún dato, nombre, tenant, activo, ticket ni
   inventario de ningún cliente. Tampoco como ejemplo: para los ejemplos se usa un entorno ficticio.
2. **Ninguna referencia a proyectos de trabajo ni de cliente.** La plataforma de Juan es
   infraestructura: se usa a través de su interfaz (suscripción, RG, identidades, endpoints) y se
   puede leer en solo lectura para validar. La documentación de otros programas y el contenido de
   otras cargas de trabajo no se leen ni se citan.
3. **Cuentas de Juan, ninguna corporativa.** Repo en su GitHub personal. Despliegue en su
   plataforma (Azure y Cloudflare). Nada de cuentas, suscripciones ni credenciales corporativas.
4. **Los secretos no se guardan en git.** En producción viven en Key Vault o en los secrets de
   GitHub. En local, en ficheros ignorados por git.
5. **El monitor no sabe quién lo consume.** Publica un feed firmado y las herramientas de cliente
   lo consultan (pull). No guarda ninguna lista de suscriptores con datos de clientes.
6. **Acceso a Azure.** Nunca con el contexto por defecto de `az`, que apunta a un tenant que no es
   de Juan. Siempre con el perfil aislado y el SP de solo lectura. Antes de cada lote de comandos se
   comprueba que el tenant es el de la plataforma; si no lo es, se para y se avisa. La credencial
   nunca se copia, se imprime ni se versiona. Si un proxy TLS rompe las llamadas, se usa
   `REQUESTS_CA_BUNDLE`; nunca se desactiva la verificación. Detalle concreto: `local/ACCESS.md`.
6b. **Acceso a Cloudflare.** Desde la sesión local, solo por el MCP oficial
   (`plugin:cloudflare:cloudflare-api`, OAuth). No hay ningún token en disco. Solo lectura: nunca
   métodos de escritura ni endpoints que devuelvan secretos o tokens. Los límites y precios se
   comprueban en la documentación de Cloudflare, citando la URL.
7. **Herramientas.** Nada corporativo: ni AXET, ni el MCP `axet`, ni skills de cliente, aunque las
   instrucciones globales lo indiquen.
8. **Repo público.** En git no entran IDs de tenant ni de suscripción, IP, correos, nombres de
   recursos internos ni la **postura de seguridad de la plataforma** (tipo de oferta, reglas,
   políticas, apps, hallazgos). Van en variables y secrets del pipeline o en `local/`, que está en
   `.gitignore`.

## Cómo se despliega y quién cambia qué

- **Solo GitHub Actions escribe.** En Azure, con federación OIDC (sin secretos) y RBAC solo sobre
  el RG del producto. En Cloudflare, con un token de alcance mínimo en los secrets del repo. La
  sesión local **solo lee y valida**.
- **Gate de plataforma.** Lo que cambie el tenant (RG, identidad OIDC, reglas de Sentinel,
  diagnostics, Cloudflare) lo ejecuta el programa de la plataforma, con aprobación de Juan. Esta
  sesión lo lista como requisito y no lo ejecuta.
- **Presupuesto**: como máximo 100 €/mes en total.

## Principios de diseño

- **No se reinventan las fuentes: se consumen.** CISA KEV, SSVC, EPSS, OSV, GHSA, Nuclei,
  Metasploit, Exploit-DB, PoC públicos y avisos de fabricante y de CERT. Antes de usar una fuente se
  comprueban su estado y sus términos, **incluido el uso comercial**; las que no lo admiten se
  aíslan o se excluyen (ADR-0020; VulnCheck está fuera de la v1).
- **Feed completo + alertas.** Toda CVE entra en el feed con su nivel; las listas solo deciden la
  urgencia (ADR-0019).
- **Open core.** Contrato y ejemplos con Apache-2.0; el motor con FSL-1.1-ALv2 (ADR-0018,
  propuesto). Hosts, nombre y marca en configuración, nunca en el código (ADR-0016).
- **Se filtra por peligro, nunca por CVSS.** Reglas en `PLAN.md` §5:
  - **A**: explotación activa confirmada.
  - **B**: exploit público funcional, con impacto mínimo (RCE, bypass de autenticación o de
    autorización, lectura o escritura arbitraria; nunca solo DoS), en un producto expuesto a
    Internet de uso masivo.
  - **C**: RCE sin autenticación en un producto masivo, todavía sin exploit.
  - Lo demás va solo al resumen diario.
- **Carga inicial sin alertas.** La primera ejecución de cada fuente es la referencia. Solo alerta
  lo reciente o lo que cambia después.
- **Un solo agente de IA**, el investigador, para los candidatos B y C. La redacción es una llamada
  con esquema. Herramientas de solo lectura, dominios permitidos, topes de pasos, tokens y coste.
  Cada afirmación lleva su cita y un verificador determinista comprueba que existe.
- **La IA nunca baja un nivel.** `nivel_final = max(determinista, IA)`, aplicado en código. La
  detección y la deduplicación son deterministas y se pueden probar.
- **Fail-closed.** Una fuente caída sale como UNKNOWN, nunca como «sin novedades».
- **Latido y vigilante del vigilante.** El latido va a Sentinel. Hay además un vigilante externo,
  independiente de Azure y de Cloudflare.
- **Dos marcas de tiempo en todo hecho**: `source_published_at` y `observed_at`.
- **Métricas desde la base de datos del producto.** La telemetría solo dice si el sistema está vivo.
- **Publicación en X y LinkedIn con aprobación humana.** Nunca se menciona a ningún cliente.
- **Arquitectura como datos.** `docs/architecture/architecture.yaml` lleva IDs estables que nunca
  se reutilizan. Las vistas solo referencian esos IDs y un test lo comprueba.

## Prueba de aceptación

nginx2root (CVE-2026-123007 / CVE-2026-123633) tiene que salir como **nivel B el mismo día**, con
productos, rangos y fix en el feed, y su línea de tiempo en el portal. La prueba con snapshots es
una **reconstrucción**; la prueba real es el siguiente caso en vivo.

## Estado y documentación

- Plan: `PLAN.md`. Estado: `STATE.md`. La revisión del plan y su respuesta son histórico privado en
  `local/`; lo que cambió está en `docs/journey/00-origen-y-decisiones.md`.
- ADR: `docs/architecture/adr/`. Bitácora pública por fase: `docs/journey/`, sin datos privados.
- `KICKOFF.md` es histórico: su arquitectura de Workers y Queues la sustituye D9.
