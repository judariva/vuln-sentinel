---
fase: F0
fecha: 2026-11-25
adr: ["0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008", "0009", "0010", "0011", "0012", "0013", "0014"]
---

# F0 · De la idea al plan

## Qué se decidió y por qué

- El núcleo pasa de Cloudflare Workers a **Azure Container Apps + PostgreSQL**. Cloudflare queda
  como borde (DNS, WAF, Access, caché). ADR-0001 a 0005.
- **Feed OSV 1.9 extendido y firmado**: un cliente cruza por purl y rango sin IA. ADR-0007 y 0008.
- **Un solo agente de IA**, con un bucle propio. El servicio gestionado de agentes de la nube
  elegida no admite el modelo preferido. ADR-0010.
- La revisión del plan añadió tres decisiones que cambian el producto:
  - **carga inicial sin alertas** (ADR-0012);
  - **B exige impacto mínimo** (ADR-0013);
  - **mínimo privilegio real en el pipeline** (ADR-0014).

## Qué falló o se corrigió

- El primer plan habría generado miles de alertas en el primer arranque: todo el histórico de KEV y
  de exploits era «nuevo».
- Un módulo de DoS habría dado nivel B.
- La cronología de nginx2root daba como hecho una hora de B que solo era una inferencia. Ahora se
  separan hechos, inferencias y desconocidos. La prueba con snapshots se llama **reconstrucción**.
- La lista de autores de confianza corría el riesgo de hacerse a la medida de la prueba. Ahora se
  genera con un criterio escrito antes de mirar el caso.
- La métrica «ventaja sobre KEV» asumía que KEV publica la hora; solo publica la fecha. Se usa la
  hora de observación, con ±15 min.

## Métricas

Todavía no hay producto en marcha: las métricas de antes y después empiezan en F1a.
