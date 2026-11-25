# Contribuir a vuln-sentinel

Gracias por querer contribuir. El proyecto es **Apache-2.0** en su totalidad (ADR-0011).

## DCO

Cada commit lleva la firma del [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "mensaje"
```

Esto añade `Signed-off-by: Nombre <correo>`, con el que declaras que tienes derecho a aportar ese
código bajo la licencia del proyecto. No hace falta CLA.

## Reglas

- Todo cambio entra por **pull request**, con la CI en verde.
- Nada de datos de clientes, ni siquiera como ejemplo. Los ejemplos usan un entorno ficticio.
- Ningún secreto, host real, dirección de donación ni identificador de infraestructura en el código.
- Cada decisión de diseño lleva su ADR en `docs/architecture/adr/`.
- Los cambios de `config/exposed-products.yaml` y `config/trusted-exploit-authors.yaml` explican su
  motivo y siguen el criterio escrito en cada fichero.

## Desarrollo

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run pytest
```
