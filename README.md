# vuln-sentinel

Monitor 24/7 de vulnerabilidades **nuevas y peligrosas**. Clasifica por peligro, no por CVSS:

- **A, inmediato**: explotación activa confirmada.
- **B, urgente**: exploit público funcional, con impacto mínimo, en un producto expuesto a
  Internet de uso masivo.
- **C, vigilar**: RCE sin autenticación en un producto masivo, todavía sin exploit.

Publica un feed **OSV 1.9 extendido y firmado** (JWS detached) que cualquier herramienta puede
cruzar con su inventario sin IA. El monitor no sabe quién lo consume.

Estado: **F0 (arranque)**. Ver [PLAN.md](PLAN.md) y [STATE.md](STATE.md).

## Desarrollo

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run pytest
```

## Licencia

Código bajo [Apache-2.0](LICENSE). Las atribuciones de los datos de terceros están en [NOTICE](NOTICE).
