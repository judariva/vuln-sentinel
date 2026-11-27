"""Migraciones de Alembic sin `alembic.ini` y conexión a PostgreSQL. Ninguna URL ni credencial en el
repo.

La URL sale de dos sitios:

- `VS_DATABASE_URL`, con o sin contraseña (local, CI, `compose.yaml`).
- En Azure (F1a), de `VS_DATABASE_HOST`, `VS_DATABASE_NAME` y `VS_DATABASE_USER` con
  `VS_DATABASE_AUTH=entra`: sin contraseña guardada. Cada conexión nueva usa como contraseña un
  token de Entra ID de la identidad gestionada del componente (`vs.azure_identity`), y TLS con
  verificación del certificado y del nombre del servidor (`sslmode=verify-full`).

Uso: `python -m vs.model.migrate upgrade head` (o `downgrade base`). Tras `upgrade`, si el entorno
trae la identidad de publicación (`VS_DATABASE_PUBLISH_ROLE` y `VS_DATABASE_PUBLISH_OID`) o la de
solo lectura de la API (`VS_DATABASE_READONLY_ROLE` y `VS_DATABASE_READONLY_OID`), crea sus roles de
Entra y les da solo los permisos que necesitan (`vs.model.roles`).
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, pool
from sqlalchemy.engine import URL, make_url

MIGRATIONS = Path(__file__).resolve().parent / "migrations"
DATABASE_URL_ENV = "VS_DATABASE_URL"
PG_PORT = 5432
# Almacén de CA del sistema en la imagen (Debian, paquete ca-certificates). Se puede cambiar.
DEFAULT_SSLROOTCERT = "/etc/ssl/certs/ca-certificates.crt"
# Los tokens de identidad gestionada duran horas; las conexiones se renuevan mucho antes.
ENTRA_POOL_RECYCLE = 1800
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def normalize_url(url: str) -> str:
    """Fuerza el driver psycopg 3: `postgresql://` en SQLAlchemy usaría psycopg2."""
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    return url


def uses_entra(env: Mapping[str, str] | None = None) -> bool:
    """Autenticación con token de Entra: `VS_DATABASE_AUTH=entra` y sin `VS_DATABASE_URL`."""
    env = os.environ if env is None else env
    return not env.get(DATABASE_URL_ENV) and env.get("VS_DATABASE_AUTH", "").strip() == "entra"


def database_url(env: Mapping[str, str] | None = None) -> str | None:
    """URL de la base de datos según el entorno, o None si no hay ninguna configurada."""
    env = os.environ if env is None else env
    url = env.get(DATABASE_URL_ENV)
    if url:
        return url
    if not uses_entra(env):
        return None
    host = env.get("VS_DATABASE_HOST", "").strip().lower()
    name = env.get("VS_DATABASE_NAME", "").strip()
    user = env.get("VS_DATABASE_USER", "").strip()
    if not (host and name and user):
        raise RuntimeError(
            "VS_DATABASE_AUTH=entra exige VS_DATABASE_HOST, VS_DATABASE_NAME y VS_DATABASE_USER."
        )
    if not _HOST_RE.fullmatch(host):
        raise RuntimeError("VS_DATABASE_HOST no es un nombre DNS válido.")
    rootcert = env.get("VS_DATABASE_SSLROOTCERT", "").strip() or DEFAULT_SSLROOTCERT
    return (
        f"postgresql+psycopg://{quote(user, safe='')}@{host}:{PG_PORT}/{quote(name, safe='')}"
        f"?sslmode=verify-full&sslrootcert={quote(rootcert, safe='/')}"
    )


def create_db_engine(
    url: str | URL,
    *,
    env: Mapping[str, str] | None = None,
    credential: Any = None,
    **kwargs: Any,
) -> Engine:
    """Motor de SQLAlchemy. Con Entra, cada conexión nueva pide (o reutiliza) el token."""
    target = make_url(normalize_url(url) if isinstance(url, str) else url)
    entra = uses_entra(env)
    if entra:
        kwargs.setdefault("pool_recycle", ENTRA_POOL_RECYCLE)
    engine = create_engine(target, **kwargs)
    if entra:
        from vs.azure_identity import POSTGRES_SCOPE, ManagedIdentityCredential

        cred = credential or ManagedIdentityCredential.from_env(env)

        @event.listens_for(engine, "do_connect")
        def _entra_token(dialect, conn_rec, cargs, cparams) -> None:
            cparams["password"] = cred.token(POSTGRES_SCOPE)

    return engine


def require_url(url: str | None = None) -> str:
    url = url or database_url()
    if not url:
        raise RuntimeError(
            f"Falta la URL de la base de datos ({DATABASE_URL_ENV} o VS_DATABASE_AUTH=entra)."
        )
    return url


def config(url: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    # ConfigParser interpreta '%': se escapa para que una contraseña con '%' no rompa.
    cfg.set_main_option("sqlalchemy.url", normalize_url(require_url(url)).replace("%", "%%"))
    return cfg


def _run(action, url: str | None, revision: str) -> str:
    url = require_url(url)
    cfg = config(url)
    engine = create_db_engine(url, poolclass=pool.NullPool)
    try:
        # env.py usa esta conexión (con el token de Entra si toca) en vez de crear su motor.
        with engine.begin() as connection:
            cfg.attributes["connection"] = connection
            action(cfg, revision)
    finally:
        engine.dispose()
    return url


def upgrade(url: str | None = None, revision: str = "head") -> None:
    _run(command.upgrade, url, revision)


def downgrade(url: str | None = None, revision: str = "base") -> None:
    _run(command.downgrade, url, revision)


def _log(event_name: str, **fields: Any) -> None:
    doc = {"at": datetime.now(UTC).isoformat(), "event": event_name, **fields}
    print(json.dumps(doc, ensure_ascii=False), flush=True)


def main(argv: list[str]) -> int:
    if len(argv) not in (1, 2) or argv[0] not in ("upgrade", "downgrade"):
        print("uso: python -m vs.model.migrate {upgrade|downgrade} [revisión]", file=sys.stderr)
        return 2
    revision = argv[1] if len(argv) == 2 else ("head" if argv[0] == "upgrade" else "base")
    if argv[0] == "downgrade":
        downgrade(revision=revision)
        _log("migrate", action="downgrade", revision=revision)
        return 0
    upgrade(revision=revision)
    from vs.model.roles import ensure_roles

    roles = ensure_roles(require_url())
    _log(
        "migrate",
        action="upgrade",
        revision=revision,
        publish_role=roles["publish"],
        readonly_role=roles["readonly"],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
