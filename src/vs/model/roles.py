"""Rol de PostgreSQL de la identidad de publicación (F1a, D-3: dos identidades).

El administrador Entra del servidor es la identidad `runtime` (la del job de migración). La
identidad `publish` solo firma el feed y necesita su propio rol, con lo justo:

- lectura de todas las tablas (arma el feed desde los hechos, niveles e historial);
- escritura solo en `feed_record`, `feed_change` (con borrado de lo caducado) y `job_state`.

El rol se crea con `pgaadauth_create_principal_with_oid`, que vive en la base de datos `postgres`
y no consulta Microsoft Graph (learn.microsoft.com/azure/postgresql/flexible-server/
how-to-manage-azure-ad-users). Los permisos se dan en la base de datos del producto, después de
cada migración, para que cubran las tablas nuevas. Todo es idempotente.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from sqlalchemy import Engine, pool, text
from sqlalchemy.engine import make_url

from vs.model.migrate import create_db_engine, normalize_url

ROLE_ENV = "VS_DATABASE_PUBLISH_ROLE"
OID_ENV = "VS_DATABASE_PUBLISH_OID"
_ROLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
_OID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# Escritura de publish, por tabla. Lo demás, solo lectura.
PUBLISH_WRITES: Mapping[str, str] = {
    "feed_record": "INSERT, UPDATE, DELETE",
    "feed_change": "INSERT, UPDATE, DELETE",
    "job_state": "INSERT, UPDATE",
}


@dataclass(frozen=True)
class Principal:
    name: str
    oid: str

    def __post_init__(self) -> None:
        if not _ROLE_RE.fullmatch(self.name):
            raise ValueError(f"{ROLE_ENV} no es un nombre de rol válido")
        if not _OID_RE.fullmatch(self.oid):
            raise ValueError(f"{OID_ENV} no es un object id válido")

    @property
    def ident(self) -> str:
        """Identificador SQL entre comillas. El nombre ya está validado: sin comillas dentro."""
        return f'"{self.name}"'


def publish_principal(env: Mapping[str, str] | None = None) -> Principal | None:
    env = os.environ if env is None else env
    name = env.get(ROLE_ENV, "").strip()
    oid = env.get(OID_ENV, "").strip().lower()
    if not name and not oid:
        return None
    if not (name and oid):
        raise ValueError(f"{ROLE_ENV} y {OID_ENV} van juntas")
    return Principal(name, oid)


def grant_statements(p: Principal) -> list[str]:
    stmts = [
        f"GRANT USAGE ON SCHEMA public TO {p.ident}",
        f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {p.ident}",
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {p.ident}",
    ]
    stmts += [f"GRANT {privs} ON {table} TO {p.ident}" for table, privs in PUBLISH_WRITES.items()]
    return stmts


def ensure_publish_role(
    app_url: str,
    env: Mapping[str, str] | None = None,
    engine_factory: Callable[..., Engine] | None = None,
) -> str:
    """Crea el rol si falta y da los permisos. Devuelve `skipped`, `granted` o `created`."""
    principal = publish_principal(env)
    if principal is None:
        return "skipped"
    engine_factory = engine_factory or create_db_engine
    result = "granted"
    admin = engine_factory(
        make_url(normalize_url(app_url)).set(database="postgres"), env=env, poolclass=pool.NullPool
    )
    try:
        with admin.begin() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = :n"), {"n": principal.name}
            ).first()
            if not exists:
                conn.execute(
                    text(
                        "SELECT * FROM pgaadauth_create_principal_with_oid"
                        "(:n, :oid, 'service', false, false)"
                    ),
                    {"n": principal.name, "oid": principal.oid},
                )
                result = "created"
    finally:
        admin.dispose()
    app = engine_factory(app_url, env=env, poolclass=pool.NullPool)
    try:
        with app.begin() as conn:
            for stmt in grant_statements(principal):
                conn.execute(text(stmt))
    finally:
        app.dispose()
    return result
