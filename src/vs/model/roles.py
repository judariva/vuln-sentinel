"""Roles de PostgreSQL de las identidades que no administran la base de datos (F1a, D-3).

El administrador Entra del servidor es la identidad `runtime` (la del job de migración). Las demás
identidades tienen su propio rol, con lo justo:

- `publish` (solo firma el feed): lectura de todas las tablas y escritura solo en `feed_record`,
  `feed_change`, `feed_signature` (con borrado de lo caducado) y `job_state`.
- `readonly` (la API, que está expuesta y no escribe): SOLO lectura. Además de los GRANT, un REVOKE
  explícito de toda escritura, para que lo siga siendo aunque alguien le diera permisos a mano.

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
READONLY_ROLE_ENV = "VS_DATABASE_READONLY_ROLE"
READONLY_OID_ENV = "VS_DATABASE_READONLY_OID"
PROFILES = ("publish", "readonly")
_ROLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
_OID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# Escritura de publish, por tabla. Lo demás, solo lectura.
PUBLISH_WRITES: Mapping[str, str] = {
    "feed_record": "INSERT, UPDATE, DELETE",
    "feed_change": "INSERT, UPDATE, DELETE",
    "feed_signature": "INSERT, UPDATE, DELETE",  # ADR-0026: firmas que sirve la API
    "job_state": "INSERT, UPDATE",
}


@dataclass(frozen=True)
class Principal:
    name: str
    oid: str
    profile: str = "publish"

    def __post_init__(self) -> None:
        if not _ROLE_RE.fullmatch(self.name):
            raise ValueError(f"{ROLE_ENV} no es un nombre de rol válido")
        if not _OID_RE.fullmatch(self.oid):
            raise ValueError(f"{OID_ENV} no es un object id válido")
        if self.profile not in PROFILES:
            raise ValueError(f"perfil de rol desconocido: {self.profile}")

    @property
    def ident(self) -> str:
        """Identificador SQL entre comillas. El nombre ya está validado: sin comillas dentro."""
        return f'"{self.name}"'


def _principal(env: Mapping[str, str], role_env: str, oid_env: str, profile: str):
    name = env.get(role_env, "").strip()
    oid = env.get(oid_env, "").strip().lower()
    if not name and not oid:
        return None
    if not (name and oid):
        raise ValueError(f"{role_env} y {oid_env} van juntas")
    return Principal(name, oid, profile)


def publish_principal(env: Mapping[str, str] | None = None) -> Principal | None:
    return _principal(os.environ if env is None else env, ROLE_ENV, OID_ENV, "publish")


def readonly_principal(env: Mapping[str, str] | None = None) -> Principal | None:
    return _principal(
        os.environ if env is None else env, READONLY_ROLE_ENV, READONLY_OID_ENV, "readonly"
    )


def grant_statements(p: Principal) -> list[str]:
    stmts = [
        f"GRANT USAGE ON SCHEMA public TO {p.ident}",
        f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {p.ident}",
    ]
    if p.profile == "readonly":
        return [
            *stmts,
            "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public"
            f" FROM {p.ident}",
            f"REVOKE CREATE ON SCHEMA public FROM {p.ident}",
        ]
    stmts.append(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {p.ident}")
    stmts += [f"GRANT {privs} ON {table} TO {p.ident}" for table, privs in PUBLISH_WRITES.items()]
    return stmts


def _ensure(
    app_url: str,
    principal: Principal,
    env: Mapping[str, str] | None,
    engine_factory: Callable[..., Engine],
) -> str:
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


def ensure_publish_role(
    app_url: str,
    env: Mapping[str, str] | None = None,
    engine_factory: Callable[..., Engine] | None = None,
) -> str:
    """Crea el rol de publish si falta y da los permisos. `skipped`, `granted` o `created`."""
    principal = publish_principal(env)
    if principal is None:
        return "skipped"
    return _ensure(app_url, principal, env, engine_factory or create_db_engine)


def ensure_roles(
    app_url: str,
    env: Mapping[str, str] | None = None,
    engine_factory: Callable[..., Engine] | None = None,
) -> dict[str, str]:
    """Roles de publish y de solo lectura. Por perfil: `skipped`, `granted` o `created`."""
    pub, ro = publish_principal(env), readonly_principal(env)
    if pub and ro and pub.name == ro.name:
        raise ValueError("el rol de solo lectura no puede ser el de publish")
    factory = engine_factory or create_db_engine
    return {
        "publish": "skipped" if pub is None else _ensure(app_url, pub, env, factory),
        "readonly": "skipped" if ro is None else _ensure(app_url, ro, env, factory),
    }
