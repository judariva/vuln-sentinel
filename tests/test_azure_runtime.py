"""F1a, runtime en Azure sin SDK: token de la identidad gestionada, PostgreSQL con Entra, rol de
publish, firma con Key Vault y API que no firma (D-3). Todo con transportes falsos: ninguna red.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from tests.test_db import db_url  # noqa: F401 - fixture: base de datos desechable
from vs.azure_identity import (
    KEY_VAULT_SCOPE,
    POSTGRES_SCOPE,
    IdentityError,
    ManagedIdentityCredential,
    scope_to_resource,
)
from vs.feed.sign import (
    KeyVaultSigner,
    LocalDevSigner,
    SignatureError,
    SigningUnavailable,
    UnavailableSigner,
    b64url,
    jwks,
    sign_detached,
    verify_detached,
)
from vs.heartbeat.client import MONITOR_SCOPE, ManagedIdentityTokenProvider
from vs.jobs.settings import Settings, SettingsError
from vs.model import roles as vs_roles
from vs.model.migrate import create_db_engine, database_url, downgrade, upgrade, uses_entra
from vs.model.roles import (
    Principal,
    ensure_publish_role,
    ensure_roles,
    grant_statements,
    publish_principal,
)

ENDPOINT = "http://localhost:42356/msi/token"
HEADER = "cabecera-secreta-de-prueba"
CLIENT = "00000000-0000-0000-0000-00000000c11e"
OID = "11111111-2222-3333-4444-555555555555"
ENTRA_ENV = {
    "VS_DATABASE_AUTH": "entra",
    "VS_DATABASE_HOST": "psql-ejemplo.postgres.database.azure.com",
    "VS_DATABASE_NAME": "vulnsentinel",
    "VS_DATABASE_USER": "id-ejemplo-runtime",
    "IDENTITY_ENDPOINT": ENDPOINT,
    "IDENTITY_HEADER": HEADER,
    "AZURE_CLIENT_ID": CLIENT,
}
KID = "test-2099-01"
DOC = b'{"id":"VS-CVE-2099-0001"}'


# -- identidad gestionada ------------------------------------------------------------------------


class FakeIdentity:
    def __init__(self, status=200, expires_in=3600, now=1_000_000.0):
        self.calls: list[tuple[str, dict]] = []
        self.status = status
        self.expires_in = expires_in
        self.now = now

    def get(self, url, *, headers, timeout):
        self.calls.append((url, dict(headers)))
        q = parse_qs(urlsplit(url).query)
        body = {
            "access_token": f"tok-{q['resource'][0]}-{len(self.calls)}",
            "expires_on": str(int(self.now + self.expires_in)),
        }
        return self.status, json.dumps(body).encode()


def credential(fake, clock=lambda: 1_000_000.0):
    return ManagedIdentityCredential.from_env(ENTRA_ENV, transport=fake, clock=clock)


def test_identity_request_uses_resource_client_id_and_header():
    fake = FakeIdentity()
    tok = credential(fake).token(POSTGRES_SCOPE)
    url, headers = fake.calls[0]
    q = parse_qs(urlsplit(url).query)
    assert url.startswith(ENDPOINT + "?")
    assert q == {
        "api-version": ["2019-08-01"],
        "resource": ["https://ossrdbms-aad.database.windows.net"],
        "client_id": [CLIENT],
    }
    assert headers == {"X-IDENTITY-HEADER": HEADER}
    assert tok == "tok-https://ossrdbms-aad.database.windows.net-1"


def test_identity_token_cached_per_resource_and_refreshed_before_expiry():
    now = [1_000_000.0]
    fake = FakeIdentity(expires_in=3600)
    cred = credential(fake, clock=lambda: now[0])
    first = cred.token(POSTGRES_SCOPE)
    assert cred.token(POSTGRES_SCOPE) == first
    cred.token(KEY_VAULT_SCOPE)
    assert len(fake.calls) == 2
    now[0] += 3600 - 299  # dentro del margen de 5 minutos: token nuevo
    assert cred.token(POSTGRES_SCOPE) != first
    assert len(fake.calls) == 3


@pytest.mark.parametrize("status", [400, 403, 500])
def test_identity_http_error_hides_secrets(status):
    with pytest.raises(IdentityError) as exc:
        credential(FakeIdentity(status=status)).token(POSTGRES_SCOPE)
    assert HEADER not in str(exc.value) and str(status) in str(exc.value)


@pytest.mark.parametrize(
    "endpoint", ["http://169.254.169.254/metadata/identity", "http://evil.example/t", "ftp://x/"]
)
def test_identity_endpoint_must_be_local_or_https(endpoint):
    with pytest.raises(IdentityError):
        ManagedIdentityCredential(CLIENT, endpoint=endpoint, header=HEADER)


def test_identity_requires_endpoint_header_and_client_id():
    with pytest.raises(IdentityError):
        ManagedIdentityCredential.from_env({})
    with pytest.raises(IdentityError):
        ManagedIdentityCredential(CLIENT, endpoint=ENDPOINT, header="")
    with pytest.raises(ValueError):
        ManagedIdentityCredential("", endpoint=ENDPOINT, header=HEADER)


def test_scope_to_resource():
    assert scope_to_resource("https://vault.azure.net/.default") == "https://vault.azure.net"
    with pytest.raises(ValueError):
        scope_to_resource("vault.azure.net/.default")


def test_heartbeat_provider_uses_managed_identity():
    fake = FakeIdentity()
    provider = ManagedIdentityTokenProvider("otro-client-id", env=ENTRA_ENV, transport=fake)
    assert provider.token(MONITOR_SCOPE).startswith("tok-https://monitor.azure.com")
    assert parse_qs(urlsplit(fake.calls[0][0]).query)["client_id"] == ["otro-client-id"]


# -- PostgreSQL con Entra ------------------------------------------------------------------------


def test_database_url_prefers_explicit_url():
    env = {**ENTRA_ENV, "VS_DATABASE_URL": "postgresql://u:p@db/x"}
    assert database_url(env) == "postgresql://u:p@db/x"
    assert not uses_entra(env)


def test_database_url_entra_without_password_and_verify_full():
    url = make_url(database_url(ENTRA_ENV))
    assert url.drivername == "postgresql+psycopg"
    assert (url.username, url.password) == ("id-ejemplo-runtime", None)
    assert (url.host, url.port, url.database) == (
        ENTRA_ENV["VS_DATABASE_HOST"],
        5432,
        "vulnsentinel",
    )
    assert url.query["sslmode"] == "verify-full"
    assert url.query["sslrootcert"] == "/etc/ssl/certs/ca-certificates.crt"


def test_database_url_none_without_configuration():
    assert database_url({}) is None
    assert database_url({"VS_DATABASE_HOST": "x.example"}) is None


@pytest.mark.parametrize("drop", ["VS_DATABASE_HOST", "VS_DATABASE_NAME", "VS_DATABASE_USER"])
def test_database_url_entra_incomplete(drop):
    env = {k: v for k, v in ENTRA_ENV.items() if k != drop}
    with pytest.raises(RuntimeError):
        database_url(env)


@pytest.mark.parametrize("host", ["localhost", "db.example.com/x", "-x.example.com", "a b.example"])
def test_database_url_entra_rejects_bad_host(host):
    with pytest.raises(RuntimeError):
        database_url({**ENTRA_ENV, "VS_DATABASE_HOST": host})


class FixedToken:
    def __init__(self):
        self.scopes: list[str] = []

    def token(self, scope):
        self.scopes.append(scope)
        return "token-de-entra"


def _do_connect(engine) -> dict:
    cparams: dict = {}
    for listener in engine.dialect.dispatch.do_connect:
        listener(engine.dialect, None, [], cparams)
    return cparams


def test_engine_with_entra_sets_token_as_password_on_each_connect():
    cred = FixedToken()
    engine = create_db_engine(database_url(ENTRA_ENV), env=ENTRA_ENV, credential=cred)
    assert _do_connect(engine) == {"password": "token-de-entra"}
    assert cred.scopes == [POSTGRES_SCOPE]
    assert engine.pool._recycle == 1800


def test_engine_without_entra_has_no_token_hook():
    engine = create_db_engine("postgresql://u:p@db/x", env={"VS_DATABASE_URL": "x"})
    assert _do_connect(engine) == {}


def test_settings_reports_incomplete_entra_as_config_error():
    env = {k: v for k, v in ENTRA_ENV.items() if k != "VS_DATABASE_HOST"}
    with pytest.raises(SettingsError, match="VS_DATABASE_HOST"):
        Settings.from_env(env).require_db()
    assert Settings.from_env(ENTRA_ENV).require_db().startswith("postgresql+psycopg://")


# -- rol de publish ------------------------------------------------------------------------------


def test_publish_principal_from_env():
    env = {"VS_DATABASE_PUBLISH_ROLE": "id-ejemplo-publish", "VS_DATABASE_PUBLISH_OID": OID}
    assert publish_principal(env) == Principal("id-ejemplo-publish", OID)
    assert publish_principal({}) is None
    with pytest.raises(ValueError):
        publish_principal({"VS_DATABASE_PUBLISH_ROLE": "id-ejemplo-publish"})


@pytest.mark.parametrize(
    "name,oid",
    [('x"; DROP ROLE a; --', OID), ("ok-name", "no-es-un-oid"), ("", OID), ("a" * 64, OID)],
)
def test_principal_rejects_injection_and_bad_ids(name, oid):
    with pytest.raises(ValueError):
        Principal(name, oid)


def test_grants_are_least_privilege():
    stmts = grant_statements(Principal("id-ejemplo-publish", OID))
    joined = "\n".join(stmts)
    assert 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "id-ejemplo-publish"' in stmts
    writes = [s for s in stmts if any(w in s for w in ("INSERT", "UPDATE", "DELETE"))]
    assert sorted(s.split(" ON ")[1].split(" TO ")[0] for s in writes) == [
        "feed_change",
        "feed_record",
        "job_state",
    ]
    for forbidden in ("ALL PRIVILEGES", "CREATE", "TRUNCATE", "SUPERUSER", "azure_pg_admin"):
        assert forbidden not in joined


class _Result:
    def __init__(self, row):
        self.row = row

    def first(self):
        return self.row


class FakeConn:
    def __init__(self, log, exists):
        self.log, self.exists = log, exists

    def execute(self, stmt, params=None):
        self.log.append((str(stmt), dict(params or {})))
        return _Result((1,) if self.exists and "pg_roles" in str(stmt) else None)


class FakeEngine:
    def __init__(self, url, log, exists):
        self.url, self.log, self.exists = url, log, exists

    def begin(self):
        engine = self

        class _Ctx:
            def __enter__(self):
                engine.log.append(("BEGIN", {"db": engine.url.database}))
                return FakeConn(engine.log, engine.exists)

            def __exit__(self, *a):
                return False

        return _Ctx()

    def dispose(self):
        pass


def _factory(log, exists):
    return lambda url, **kw: FakeEngine(make_url(url) if isinstance(url, str) else url, log, exists)


APP_URL = (
    "postgresql+psycopg://id-ejemplo-runtime@db.example.com:5432/vulnsentinel?sslmode=verify-full"
)
ROLE_ENV = {"VS_DATABASE_PUBLISH_ROLE": "id-ejemplo-publish", "VS_DATABASE_PUBLISH_OID": OID}


def test_ensure_publish_role_creates_in_postgres_db_and_grants_in_app_db():
    log: list = []
    assert ensure_publish_role(APP_URL, ROLE_ENV, _factory(log, exists=False)) == "created"
    dbs = [p["db"] for s, p in log if s == "BEGIN"]
    assert dbs == ["postgres", "vulnsentinel"]
    create = [(s, p) for s, p in log if "pgaadauth_create_principal_with_oid" in s]
    assert create and create[0][1] == {"n": "id-ejemplo-publish", "oid": OID}
    assert "'service', false, false" in create[0][0]
    assert sum(s.startswith("GRANT") for s, _ in log) == len(
        grant_statements(Principal(**{"name": "id-ejemplo-publish", "oid": OID}))
    )


def test_ensure_publish_role_is_idempotent_and_optional():
    log: list = []
    assert ensure_publish_role(APP_URL, ROLE_ENV, _factory(log, exists=True)) == "granted"
    assert not any("pgaadauth" in s for s, _ in log)
    assert ensure_publish_role(APP_URL, {}, _factory([], exists=False)) == "skipped"


RO_OID = "99999999-8888-7777-6666-555555555555"
RO_ENV = {"VS_DATABASE_READONLY_ROLE": "id-ejemplo-api", "VS_DATABASE_READONLY_OID": RO_OID}


def test_readonly_grants_only_read_and_revoke_writes():
    stmts = grant_statements(Principal("id-ejemplo-api", RO_OID, "readonly"))
    grants = [s for s in stmts if s.startswith("GRANT")]
    assert grants == [
        'GRANT USAGE ON SCHEMA public TO "id-ejemplo-api"',
        'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "id-ejemplo-api"',
    ]
    assert any(s.startswith("REVOKE INSERT, UPDATE, DELETE, TRUNCATE") for s in stmts)
    assert not any(t in " ".join(grants) for t in ("INSERT", "UPDATE", "DELETE", "SEQUENCES"))


def test_principal_profile_is_closed_list():
    with pytest.raises(ValueError):
        Principal("id-ejemplo-api", RO_OID, "admin")


def test_ensure_roles_creates_both_profiles():
    log: list = []
    res = ensure_roles(APP_URL, {**ROLE_ENV, **RO_ENV}, _factory(log, exists=False))
    assert res == {"publish": "created", "readonly": "created"}
    created = [p["n"] for s, p in log if "pgaadauth_create_principal_with_oid" in s]
    assert created == ["id-ejemplo-publish", "id-ejemplo-api"]
    assert ensure_roles(APP_URL, ROLE_ENV, _factory([], exists=True)) == {
        "publish": "granted",
        "readonly": "skipped",
    }
    with pytest.raises(ValueError):
        ensure_roles(
            APP_URL,
            {
                **ROLE_ENV,
                "VS_DATABASE_READONLY_ROLE": "id-ejemplo-publish",
                "VS_DATABASE_READONLY_OID": RO_OID,
            },
            _factory([], exists=False),
        )


@pytest.mark.db
@pytest.mark.skipif(not os.environ.get("VS_TEST_DATABASE_URL"), reason="sin VS_TEST_DATABASE_URL")
def test_readonly_role_on_real_postgres(db_url):  # noqa: F811 - fixture importada de test_db
    """Solo lectura de verdad: aunque alguien le diera INSERT a mano, tras migrate no lo tiene."""
    upgrade(db_url)
    role = f"vs-test-api-{uuid.uuid4().hex[:8]}"
    engine = create_engine(db_url)
    try:
        with engine.begin() as conn:
            conn.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
            conn.execute(text(f'GRANT INSERT, DELETE ON vulnerability, job_state TO "{role}"'))
            for stmt in grant_statements(Principal(role, RO_OID, "readonly")):
                conn.execute(text(stmt))
        with engine.connect() as conn:
            tables = [
                r[0]
                for r in conn.execute(
                    text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                )
            ]

            def can(table: str, priv: str) -> bool:
                q = text("SELECT has_table_privilege(:r, :t, :p)")
                return bool(
                    conn.execute(q, {"r": role, "t": f"public.{table}", "p": priv}).scalar()
                )

            assert tables and all(can(t, "SELECT") for t in tables)
            for priv in ("INSERT", "UPDATE", "DELETE", "TRUNCATE"):
                assert not any(can(t, priv) for t in tables), priv
    finally:
        with engine.begin() as conn:
            conn.execute(text(f'DROP OWNED BY "{role}"'))
            conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
        engine.dispose()
        downgrade(db_url)


@pytest.mark.db
@pytest.mark.skipif(not os.environ.get("VS_TEST_DATABASE_URL"), reason="sin VS_TEST_DATABASE_URL")
def test_publish_grants_on_real_postgres(db_url):  # noqa: F811 - fixture importada de test_db
    """Los GRANT reales sobre el esquema migrado: lee todo y solo escribe en sus tres tablas."""
    upgrade(db_url)
    role = f"vs-test-publish-{uuid.uuid4().hex[:8]}"
    engine = create_engine(db_url)
    try:
        with engine.begin() as conn:
            conn.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
            for stmt in grant_statements(Principal(role, OID)):
                conn.execute(text(stmt))
        with engine.connect() as conn:
            tables = [
                r[0]
                for r in conn.execute(
                    text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                )
            ]

            def can(table: str, priv: str) -> bool:
                q = text("SELECT has_table_privilege(:r, :t, :p)")
                return bool(
                    conn.execute(q, {"r": role, "t": f"public.{table}", "p": priv}).scalar()
                )

            assert tables and all(can(t, "SELECT") for t in tables)
            writable = {t for t in tables if can(t, "INSERT") or can(t, "UPDATE")}
            deletable = {t for t in tables if can(t, "DELETE")}
            assert writable == {"feed_record", "feed_change", "job_state"}
            assert deletable == {"feed_record", "feed_change"}
            assert not any(can(t, "TRUNCATE") for t in tables)
    finally:
        with engine.begin() as conn:
            conn.execute(text(f'DROP OWNED BY "{role}"'))
            conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
        engine.dispose()
        downgrade(db_url)


# -- Key Vault -----------------------------------------------------------------------------------

VAULT = "https://kv-ejemplo.vault.azure.net"
VERSION = "0123456789abcdef0123456789abcdef"


class FakeVault:
    """Key Vault simulado con una clave P-256 local: `get` y `sign` como la API REST 7.4."""

    def __init__(self, signer=None, *, sign_with=None, status=200):
        self.key = signer or LocalDevSigner.generate("kv")
        self.sign_with = sign_with or self.key
        self.status = status
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, url, *, headers, body, timeout):
        self.calls.append((method, url, dict(headers)))
        if self.status != 200:
            return self.status, b""
        path = urlsplit(url).path
        assert parse_qs(urlsplit(url).query)["api-version"] == ["7.4"]
        if method == "GET":
            jwk = self.key.public_jwk()
            key = {
                "kid": f"{VAULT}/keys/feed-signing-es256/{VERSION}",
                "kty": "EC",
                "crv": "P-256",
                "x": jwk["x"],
                "y": jwk["y"],
                "key_ops": ["sign", "verify"],
            }
            return 200, json.dumps({"key": key}).encode()
        assert method == "POST" and path.endswith(f"/{VERSION}/sign")
        req = json.loads(body)
        assert req["alg"] == "ES256"
        digest = base64.urlsafe_b64decode(req["value"] + "==")
        return 200, json.dumps({"value": b64url(self.sign_with.sign_digest(digest))}).encode()


def kv_signer(vault, uri=f"{VAULT}/keys/feed-signing-es256"):
    return KeyVaultSigner.from_uri(uri, KID, FixedToken(), transport=vault)


def test_key_vault_signature_verifies_with_published_jwks():
    vault = FakeVault()
    signer = kv_signer(vault)
    jws = sign_detached(DOC, signer)
    assert verify_detached(jws, DOC, jwks([signer])) == KID
    assert signer.key_version == VERSION
    assert signer.public_jwk()["kid"] == KID and "d" not in signer.public_jwk()
    methods = [m for m, _, _ in vault.calls]
    assert methods == ["GET", "POST"]
    assert all(h["Authorization"] == "Bearer token-de-entra" for _, _, h in vault.calls)


def test_key_vault_signature_from_another_key_is_rejected():
    vault = FakeVault(sign_with=LocalDevSigner.generate("otra"))
    with pytest.raises(SignatureError, match="no casa"):
        kv_signer(vault).sign(DOC)


def test_key_vault_pinned_version_must_match():
    vault = FakeVault()
    signer = kv_signer(vault, f"{VAULT}/keys/feed-signing-es256/{'f' * 32}")
    with pytest.raises(SignatureError, match="otra versión"):
        signer.sign(DOC)


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_key_vault_http_errors(status):
    with pytest.raises(SignatureError, match=str(status)):
        kv_signer(FakeVault(status=status)).sign(DOC)


@pytest.mark.parametrize(
    "uri",
    [
        "http://kv-ejemplo.vault.azure.net/keys/k",
        "https://kv-ejemplo.vault.azure.net.evil.example/keys/k",
        "https://kv-ejemplo.vault.azure.net/secrets/k",
        "https://kv-ejemplo.vault.azure.net/keys/k/no-es-version",
    ],
)
def test_key_vault_uri_rejected(uri):
    with pytest.raises(ValueError):
        KeyVaultSigner.from_uri(uri, KID, FixedToken())


def test_key_vault_signer_imports_no_azure_sdk():
    assert not any(m == "azure" or m.startswith("azure.") for m in sys.modules)


# -- elección del firmante -----------------------------------------------------------------------


class _Feed:
    key_id = KID


def test_signer_key_vault_when_uri_present(monkeypatch):
    monkeypatch.setenv("IDENTITY_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("IDENTITY_HEADER", HEADER)
    monkeypatch.setenv("AZURE_CLIENT_ID", CLIENT)
    env = {**ENTRA_ENV, "VS_SIGNING_KEY_URI": f"{VAULT}/keys/feed-signing-es256"}
    assert isinstance(Settings.from_env(env).signer(_Feed()), KeyVaultSigner)


def test_signer_in_azure_never_uses_dev_key():
    settings = Settings.from_env(ENTRA_ENV)
    with pytest.raises(SettingsError, match="VS_SIGNING_KEY_URI"):
        settings.signer(_Feed())
    signer = settings.signer(_Feed(), required=False)
    assert isinstance(signer, UnavailableSigner) and signer.kid == KID
    with pytest.raises(SigningUnavailable):
        signer.sign(DOC)
    with pytest.raises(SigningUnavailable):
        signer.public_jwk()


# -- API sin firma -------------------------------------------------------------------------------


def test_api_without_signer_serves_json_and_503_for_signatures():
    from tests.test_api import make_app
    from tests.test_feed import CONFIG, run_day

    _, pub = run_day()
    pub.signer = UnavailableSigner(CONFIG.key_id)
    client, _ = make_app(publisher=pub)
    ident = sorted(pub.published_records())[0]
    assert client.get(f"/v1/vulns/{ident}.json").status_code == 200
    for path in (
        f"/v1/vulns/{ident}.json.jws",
        "/.well-known/vuln-sentinel/keys.json",
        "/v1/feed/alerts/latest.json.jws",
    ):
        resp = client.get(path)
        assert resp.status_code == 503, path
        assert resp.json()["error"] == "signing_unavailable"


# -- contrato módulo ↔ app -----------------------------------------------------------------------
# El primer despliegue pasó todas las puertas de infraestructura y ningún componente arrancó: el
# módulo ponía unas variables y la app leía otras. Estos tests leen las variables del módulo.

MODULE = Path(__file__).resolve().parents[1] / "infra" / "terraform" / "modules" / "vuln-sentinel"


def _block(text: str, name: str) -> str:
    m = re.search(rf"^\s*{name}\s*=\s*\{{(.*?)^\s*\}}", text, re.S | re.M)
    assert m, f"no encuentro el bloque {name} en el módulo"
    return m.group(1)


def _module_env() -> dict[str, str]:
    main = (MODULE / "main.tf").read_text(encoding="utf-8")
    env: dict[str, str] = {}
    for key, value in re.findall(r"^\s*(VS_[A-Z_]+)\s*=\s*(.+?)\s*$", _block(main, "db_env"), re.M):
        literal = re.fullmatch(r'"([^"]*)"', value)
        env[key] = literal.group(1) if literal else f"<{key}>"
    return env


def test_module_db_env_is_what_the_app_reads():
    env = _module_env()
    assert env.get("VS_DATABASE_AUTH") == "entra"
    apps_jobs = (MODULE / "apps.tf").read_text() + (MODULE / "jobs.tf").read_text()
    for name in ("VS_DATABASE_USER", "AZURE_CLIENT_ID"):
        assert apps_jobs.count(f'"{name}"') >= 2, f"{name} tiene que ir a la API y a los jobs"
    # Lo que Terraform resuelve en el apply (FQDN, nombre de la BD) y lo que inyecta Container Apps.
    env.update(
        {
            "VS_DATABASE_HOST": "psql-ejemplo-0000.postgres.database.azure.com",
            "VS_DATABASE_NAME": "vulnsentinel",
            "VS_DATABASE_USER": "id-ejemplo-runtime",
            "IDENTITY_ENDPOINT": ENDPOINT,
            "IDENTITY_HEADER": HEADER,
            "AZURE_CLIENT_ID": CLIENT,
        }
    )
    assert set(_module_env()) <= set(env)
    settings = Settings.from_env(env)
    assert uses_entra(env) and settings.azure
    assert settings.require_db().startswith("postgresql+psycopg://id-ejemplo-runtime@")


def test_module_job_env_names_match_the_code():
    main = (MODULE / "main.tf").read_text(encoding="utf-8")
    assert "VS_SIGNING_KEY_URI = var.signing_key_id" in _block(main, "publish")
    migrate = re.sub(r"\s+", " ", _block(main, "migrate"))
    assert f"{vs_roles.ROLE_ENV} = var.identities.publish.name" in migrate
    assert f"{vs_roles.OID_ENV} = var.identities.publish.principal_id" in migrate
    flat = re.sub(r"\s+", " ", main)
    assert f"{vs_roles.READONLY_ROLE_ENV} = var.identities.api.name" in flat
    assert f"{vs_roles.READONLY_OID_ENV} = var.identities.api.principal_id" in flat
