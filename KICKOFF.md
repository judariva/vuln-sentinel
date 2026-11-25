# Kickoff · plan de vuln-sentinel

Lee `CLAUDE.md` y entra en **plan mode**. No escribas código hasta que Juan apruebe el plan.

## Por qué existe

Con la IA se publican más vulnerabilidades, y más rápido. La mayoría no importan. Las pocas que
sí importan (explotadas, con exploit público o en productos expuestos a Internet de uso masivo)
tienen que verse **el mismo día** y despertar a las herramientas de cada cliente, que deciden
dentro de su propio entorno si les afecta. Hoy esa señal llega tarde, a veces por el propio
proveedor del cliente.

## Qué tiene que salir del plan

1. **El contrato del feed.** Es lo más importante: de él depende que el cliente pueda cruzar con
   su inventario sin IA. Por alerta:
   - id estable
   - nivel A/B/C y el motivo
   - CVE
   - productos: ecosistema, paquete, purl o CPE, rangos afectados y corregidos
   - señales: KEV, SSVC, EPSS y su salto, PoC/exploit con su fuente, fix y mitigación
   - fuentes con su URL y fecha
   - qué ha cambiado («nuevo» o «cambió»: entra en KEV, aparece PoC, sale el fix)
   - firma y versión del esquema
2. **Las fuentes**: tabla con qué aporta cada una, la frecuencia, los límites, los términos de
   uso y el estado actual (comprobado, no de memoria). Lo que ya existe se reutiliza; por ejemplo,
   valorar si OpenCVE u OSV cubren la ingesta.
3. **El criterio A/B/C**, en forma de reglas comprobables, y la lista mantenida de productos
   expuestos a Internet de uso masivo.
4. **La arquitectura en Cloudflare**:
   - Workers + Cron Triggers, Queues para repartir por fuente, D1 o KV para el estado y la
     deduplicación, R2 si hace falta
   - límites de CPU, memoria y subrequests, y cómo se respetan
   - el latido y el vigilante del vigilante
5. **La IA**: dónde entra (confirmar sin autenticación, remoto y masivo; redactar), con qué modelo
   (Workers AI o API de Anthropic), coste y cómo se evita que baje un nivel o se invente algo.
6. **Publicación**:
   - Teams: webhook de Power Automate, Adaptive Card.
   - X y LinkedIn: plantilla, aprobación humana y límites de frecuencia.
   - El resumen diario.
7. **Las pruebas**: casos reales a reproducir (como mínimo nginx2root), una prueba de ruido (una
   USN de kernel con cientos de CVE no puede generar cientos de alertas) y una prueba de fallo
   (una fuente caída da UNKNOWN).
8. **Los costes** mensuales estimados y el plan de despliegue por fases.

## Restricciones

- Las del `CLAUDE.md`: solo información pública, cuentas personales y sin datos de clientes.
- Si una decisión depende de Juan (cuentas, presupuesto, qué publicar), se pregunta, no se supone.
