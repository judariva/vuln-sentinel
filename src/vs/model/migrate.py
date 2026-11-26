"""Migraciones de Alembic sin `alembic.ini`: la URL de la base de datos llega por parámetro o por
la variable de entorno `VS_DATABASE_URL`, nunca escrita en el repo.

Uso: `uv run python -m vs.model.migrate upgrade head` (o `downgrade base`).
"""

import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

MIGRATIONS = Path(__file__).resolve().parent / "migrations"
DATABASE_URL_ENV = "VS_DATABASE_URL"


def normalize_url(url: str) -> str:
    """Fuerza el driver psycopg 3: `postgresql://` en SQLAlchemy usaría psycopg2."""
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    return url


def config(url: str | None = None) -> Config:
    url = url or os.environ.get(DATABASE_URL_ENV)
    if not url:
        raise RuntimeError(f"Falta la URL de la base de datos ({DATABASE_URL_ENV}).")
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    # ConfigParser interpreta '%': se escapa para que una contraseña con '%' no rompa.
    cfg.set_main_option("sqlalchemy.url", normalize_url(url).replace("%", "%%"))
    return cfg


def upgrade(url: str | None = None, revision: str = "head") -> None:
    command.upgrade(config(url), revision)


def downgrade(url: str | None = None, revision: str = "base") -> None:
    command.downgrade(config(url), revision)


def main(argv: list[str]) -> int:
    if len(argv) not in (1, 2) or argv[0] not in ("upgrade", "downgrade"):
        print("uso: python -m vs.model.migrate {upgrade|downgrade} [revisión]", file=sys.stderr)
        return 2
    action = upgrade if argv[0] == "upgrade" else downgrade
    if len(argv) == 2:
        action(revision=argv[1])
    else:
        action()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
