"""API de solo lectura (T6): endpoints, ETag/304, cursor y 410, /admin con JWT de Access,
derechos (la API pública nunca sirve `restricted`) y donaciones desactivadas.

Los datos salen del mismo montaje que `tests/test_feed.py` (C → B → A, una CVE `none` y una cuyo
único A es `restricted`). CVE `CVE-2099-*` y hosts ficticios.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, date, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.pool import StaticPool

from tests.test_feed import (
    CLIENTS,
    CONFIG,
    CVE_EXPOSED,
    CVE_OTHER,
    CVE_RESTRICTED,
    LISTS,
    ROOT,
    T3,
    run_day,
)
from vs.api import ApiConfig, ApiConfigError, create_app
from vs.api.access import HEADER, AccessConfig, AccessVerifier
from vs.feed.osv import alert_id, sha256_hex
from vs.feed.publish import FeedPublisher
from vs.feed.rights import Audience
from vs.feed.sign import LocalDevSigner, b64url, verify_detached
from vs.instance import load_instance
from vs.metrics.store import MemoryMetricsReader, MetricRow, SqlMetricsReader
from vs.model.schema import MetricDaily
from vs.sources.base import LicenseClass

INSTANCE = load_instance(ROOT / "config" / "instance.public.yaml")
NOW = datetime(2099, 3, 2, 10, 0, tzinfo=UTC)  # el 2099-03-01 (T1..T3) ya está cerrado
DAY = "2099-03-01"
RESTRICTED_MARKERS = ("RESTRICTED-PAYLOAD-DO-NOT-PUBLISH", "synthetic-restricted", "restricted.")

TEAM = "https://team.example.invalid"
AUD = "example-aud-tag"
ADMIN_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ADMIN_KID = "access-test-kid"


def metric_rows() -> list[MetricRow]:
    d1, d2 = date(2099, 2, 28), date(2099, 3, 1)
    return [
        MetricRow(d1, "cost.eur", "azure", 2.5),
        MetricRow(d1, "cost.eur", "cloudflare", 0.25),
        MetricRow(d2, "cost.eur", "azure", 3.0),
        MetricRow(d2, "funnel.ingested", "", 587.0),
        MetricRow(d2, "funnel.alerted", "B", 1.0),
        MetricRow(d2, "donations.sats", "lightning", 21000.0),
        MetricRow(d2, "donations.count", "lightning", 2.0),
        MetricRow(d1, "donations.sats", "onchain", 50000.0),
        MetricRow(d1, "donations.count", "onchain", 1.0),
    ]


def _int_b64(n: int) -> str:
    return b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def access_jwks() -> dict:
    pub = ADMIN_KEY.public_key().public_numbers()
    return {"keys": [{"kty": "RSA", "kid": ADMIN_KID, "alg": "RS256", "n": _int_b64(pub.n),
                      "e": _int_b64(pub.e)}]}  # fmt: skip


def access_jwt(*, key=ADMIN_KEY, kid=ADMIN_KID, alg="RS256", **claims) -> str:
    now = int(time.time())
    body = {"iss": TEAM, "aud": [AUD], "exp": now + 300, "iat": now, "sub": "test-subject"}
    body.update(claims)
    head = b64url(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    payload = b64url(json.dumps(body).encode())
    signing = f"{head}.{payload}".encode()
    sig = key.sign(signing, padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{payload}.{b64url(sig)}"


def make_app(
    *,
    now=NOW,
    donations=False,
    access: AccessConfig | None = None,
    publisher=None,
    metrics=None,
):
    if publisher is None:
        _, publisher = run_day()
    verifier = AccessVerifier(access or AccessConfig(TEAM, AUD), jwks=access_jwks)
    cfg = ApiConfig(
        instance=INSTANCE,
        publisher=publisher,
        metrics=metrics or MemoryMetricsReader(metric_rows()),
        access=verifier,
        donations_enabled=donations,
        clock=lambda: now,
    )
    return TestClient(create_app(cfg)), publisher


@pytest.fixture(scope="module")
def api():
    return make_app()


@pytest.fixture
def client(api):
    return api[0]


@pytest.fixture
def pub(api):
    return api[1]


def body(resp) -> dict:
    return json.loads(resp.content)


def public_paths(pub) -> list[str]:
    ids = sorted({e.id for e in pub.logs["all"].entries()})
    paths = [
        "/v1/feed/all/changes",
        "/v1/feed/alerts/changes",
        "/v1/feed/all/changes.jws",
        "/v1/feed/alerts/changes.jws",
        "/v1/feed/alerts/latest.json",
        "/v1/feed/alerts/latest.json.jws",
        f"/v1/digest/{DAY}.json",
        f"/v1/digest/{DAY}.json.jws",
        "/.well-known/vuln-sentinel/keys.json",
        f"/v1/metrics/daily.json?from=2099-02-01&to={DAY}",
        "/v1/metrics/cost.json?from=2099-01&to=2099-03",
    ]
    for ident in ids:
        paths += [f"/v1/vulns/{ident}.json", f"/v1/vulns/{ident}.json.jws"]
    return paths


# -- endpoints -------------------------------------------------------------------------------------


def test_every_public_endpoint_answers_with_schema_header(client, pub):
    for path in public_paths(pub):
        resp = client.get(path)
        assert resp.status_code == 200, (path, resp.text)
        assert resp.headers["X-VS-Schema"] == "1.0.0", path
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert "Cache-Control" in resp.headers or path.startswith("/v1/vulns/"), path


def test_healthz_for_probes_is_cheap_and_not_cached(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert body(resp) == {"status": "ok"}
    assert resp.headers["Cache-Control"] == "no-store"
    assert client.post("/healthz").status_code == 405


def test_changes_all_and_alerts(client):
    all_ = body(client.get("/v1/feed/all/changes"))
    alerts = body(client.get("/v1/feed/alerts/changes"))
    assert all_["feed"] == "all" and alerts["feed"] == "alerts"
    assert {e["id"] for e in all_["entries"]} == {
        alert_id(CVE_EXPOSED),
        alert_id(CVE_OTHER),
        alert_id(CVE_RESTRICTED),
    }
    assert all(e["level"] != "none" for e in alerts["entries"])
    assert alert_id(CVE_OTHER) not in {e["id"] for e in alerts["entries"]}
    resp = client.get("/v1/feed/all/changes")
    assert resp.headers["Cache-Control"] == "public, max-age=60"
    assert resp.headers["Content-Type"].startswith("application/json")


def test_changes_cursor_paging_is_complete(client, pub):
    seen, cursor = [], None
    for _ in range(20):
        params = {"limit": "1"} | ({"since": cursor} if cursor else {})
        page = body(client.get("/v1/feed/all/changes", params=params))
        seen += [(e["modified"], e["id"]) for e in page["entries"]]
        cursor = page["next"]
        if not page["has_more"]:
            break
    expected = [(e.to_json()["modified"], e.id) for e in pub.logs["all"].entries()]
    assert seen == expected


def test_changes_bad_cursor_and_limit_give_400(client):
    for params in ({"since": "basura"}, {"limit": "abc"}, {"limit": "0"}, {"limit": "-1"}):
        resp = client.get("/v1/feed/all/changes", params=params)
        assert resp.status_code == 400, params
        assert body(resp)["error"] == "bad_request"
        assert resp.headers["Cache-Control"] == "no-store"
        assert resp.headers["X-VS-Schema"] == "1.0.0"
    assert client.get("/v1/feed/otro/changes").status_code == 404


def test_cursor_beyond_retention_gives_410_with_snapshot(pub):
    old_cursor = pub.logs["all"].entries()[0].cursor
    late, _ = make_app(now=T3 + timedelta(days=40), publisher=pub)
    for path in ("/v1/feed/all/changes", "/v1/feed/all/changes.jws"):
        resp = late.get(path, params={"since": old_cursor})
        assert resp.status_code == 410
        doc = body(resp)
        assert doc["error"] == "gone"
        assert doc["snapshot"].startswith(CONFIG.api_base + "/v1/feed/all/snapshot/")
        assert resp.headers["Cache-Control"] == "no-store"


def test_alerts_latest(client):
    doc = body(client.get("/v1/feed/alerts/latest.json"))
    assert doc["kind"] == "alerts_latest"
    levels = {a["id"]: a["level"] for a in doc["alerts"]}
    assert levels[alert_id(CVE_EXPOSED)] == "A"
    assert alert_id(CVE_OTHER) not in levels


def test_vuln_etag_is_hash_and_304(client, pub):
    ident = alert_id(CVE_EXPOSED)
    resp = client.get(f"/v1/vulns/{ident}.json")
    assert resp.status_code == 200
    digest = sha256_hex(resp.content)
    assert resp.headers["ETag"] == f'"{digest}"'
    last = [e for e in pub.logs["all"].entries() if e.id == ident][-1]
    assert last.sha256 == digest
    assert body(resp)["id"] == ident

    for tag in (f'"{digest}"', f'W/"{digest}"', f'"otro", "{digest}"', "*"):
        cached = client.get(f"/v1/vulns/{ident}.json", headers={"If-None-Match": tag})
        assert cached.status_code == 304, tag
        assert cached.content == b""
        assert cached.headers["ETag"] == f'"{digest}"'
        assert cached.headers["X-VS-Schema"] == "1.0.0"
    stale = client.get(f"/v1/vulns/{ident}.json", headers={"If-None-Match": '"0000"'})
    assert stale.status_code == 200 and stale.content == resp.content


def test_unknown_or_bad_vuln_is_404(client):
    assert client.get("/v1/vulns/VS-CVE-2099-9999.json").status_code == 404
    assert client.get("/v1/vulns/CVE-2099-1001.json").status_code == 404
    assert client.get("/v1/vulns/..%2F..%2Fetc.json").status_code == 404


def test_every_document_has_valid_detached_signature(client, pub):
    keys = body(client.get("/.well-known/vuln-sentinel/keys.json"))
    docs = [
        "/v1/feed/all/changes",
        "/v1/feed/alerts/changes",
        "/v1/feed/alerts/latest.json",
        f"/v1/digest/{DAY}.json",
        f"/v1/vulns/{alert_id(CVE_EXPOSED)}.json",
    ]
    for path in docs:
        doc = client.get(path)
        jws_path = (
            path.replace("/changes", "/changes.jws")
            if path.endswith("changes")
            else (path + ".jws")
        )
        jws = client.get(jws_path)
        assert jws.headers["Content-Type"].startswith("application/jose"), path
        assert verify_detached(jws.text, doc.content, keys) == CONFIG.key_id, path
        with pytest.raises(ValueError):
            verify_detached(jws.text, doc.content + b" ", keys)


def test_keys_has_no_private_material(client):
    resp = client.get("/.well-known/vuln-sentinel/keys.json")
    keys = body(resp)["keys"]
    assert [k["kid"] for k in keys] == [CONFIG.key_id]
    assert all("d" not in k for k in keys)


def test_keys_rotation_serves_previous_keys(pub):
    old = LocalDevSigner.generate("example-2025-12")
    cfg = ApiConfig(
        instance=INSTANCE,
        publisher=pub,
        metrics=MemoryMetricsReader(),
        previous_signers=(old,),
        clock=lambda: NOW,
    )
    keys = body(TestClient(create_app(cfg)).get("/.well-known/vuln-sentinel/keys.json"))["keys"]
    assert [k["kid"] for k in keys] == [CONFIG.key_id, "example-2025-12"]


def test_digest_of_closed_day(client):
    resp = client.get(f"/v1/digest/{DAY}.json")
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "public, max-age=31536000, immutable"
    doc = body(resp)
    assert doc["kind"] == "digest" and doc["day"] == DAY
    by_id = {e["id"]: e for e in doc["entries"]}
    assert by_id[alert_id(CVE_EXPOSED)]["level"] == "A"
    assert by_id[alert_id(CVE_EXPOSED)]["types"][0] == "new"
    assert by_id[alert_id(CVE_OTHER)]["level"] == "none"
    assert doc["counts"]["A"] == 1 and sum(doc["counts"].values()) == len(doc["entries"])
    again = client.get(f"/v1/digest/{DAY}.json")
    assert again.content == resp.content  # día cerrado: mismos bytes


def test_digest_errors(pub):
    client, _ = make_app(publisher=pub)
    assert client.get("/v1/digest/2099-03-02.json").status_code == 404  # hoy: no cerrado
    assert client.get("/v1/digest/2099-13-01.json").status_code == 400
    assert client.get("/v1/digest/ayer.json").status_code == 400
    late, _ = make_app(now=T3 + timedelta(days=40), publisher=pub)
    resp = late.get(f"/v1/digest/{DAY}.json")
    assert resp.status_code == 410 and body(resp)["snapshot"].startswith(CONFIG.api_base)


# -- métricas ----------------------------------------------------------------------------------


def test_metrics_daily_from_metric_daily(client):
    resp = client.get("/v1/metrics/daily.json", params={"from": "2099-02-28", "to": DAY})
    doc = body(resp)
    assert resp.headers["Cache-Control"] == "public, max-age=60"
    metrics = {(r["day"], r["metric"], r["dimension"]): r["value"] for r in doc["rows"]}
    assert metrics[(DAY, "funnel.ingested", "")] == 587.0
    assert metrics[("2099-02-28", "cost.eur", "azure")] == 2.5
    params = {"from": DAY, "to": DAY, "metric": "funnel.alerted"}
    only = body(client.get("/v1/metrics/daily.json", params=params))
    assert [r["metric"] for r in only["rows"]] == ["funnel.alerted"]


def test_metrics_default_range_and_limits(client):
    doc = body(client.get("/v1/metrics/daily.json"))
    assert doc["to"] == DAY  # ayer respecto a NOW
    assert (date.fromisoformat(doc["to"]) - date.fromisoformat(doc["from"])).days == 29
    for params in (
        {"from": "2099-03-02", "to": "2099-03-01"},
        {"from": "2097-01-01", "to": "2099-03-01"},
        {"from": "01/03/2099"},
        {"metric": "DROP TABLE"},
    ):
        assert client.get("/v1/metrics/daily.json", params=params).status_code == 400, params
    assert client.get("/v1/metrics/cost.json", params={"from": "2099-1"}).status_code == 400
    assert client.get("/v1/metrics/cost.json", params={"from": "2090-01"}).status_code == 400


def test_cost_without_donations(client):
    doc = body(client.get("/v1/metrics/cost.json", params={"from": "2099-02", "to": "2099-03"}))
    feb, mar = doc["months"]
    assert feb == {"month": "2099-02", "cost_eur": 2.75,
                   "cost_by_provider": {"azure": 2.5, "cloudflare": 0.25}}  # fmt: skip
    assert mar["cost_eur"] == 3.0


def test_cost_with_donations_enabled(pub):
    client, _ = make_app(donations=True, publisher=pub)
    doc = body(client.get("/v1/metrics/cost.json", params={"from": "2099-02", "to": "2099-03"}))
    feb, mar = doc["months"]
    assert feb["cost_eur"] == 2.75
    assert feb["donations_sats"] == 50000 and feb["donations_count"] == 1
    assert mar["donations_by_channel"] == {"lightning": 21000}
    daily = body(client.get("/v1/metrics/daily.json", params={"metric": "donations.sats"}))
    assert {r["dimension"] for r in daily["rows"]} == {"lightning", "onchain"}


def test_donations_disabled_no_donation_data_anywhere(client, pub):
    for path in public_paths(pub):
        resp = client.get(path)
        assert b"donation" not in resp.content.lower(), path
    assert client.get("/v1/metrics/daily.json", params={"metric": "donations.sats"}).status_code \
        == 404  # fmt: skip
    cost = body(client.get("/v1/metrics/cost.json"))
    assert all(set(m) == {"month", "cost_eur", "cost_by_provider"} for m in cost["months"])


def test_sql_metrics_reader_only_selects():
    # Una sola conexión: la API ejecuta los endpoints en otro hilo.
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    MetricDaily.__table__.create(engine)
    with engine.begin() as conn:
        conn.execute(
            MetricDaily.__table__.insert(),
            [{"day": r.day, "metric": r.metric, "dimension": r.dimension, "value": r.value}
             for r in metric_rows()],
        )  # fmt: skip
    statements = []
    event.listen(engine, "before_cursor_execute",
                 lambda conn, cursor, stmt, *a: statements.append(stmt))  # fmt: skip
    reader = SqlMetricsReader(engine)
    rows = reader.rows(date(2099, 3, 1), date(2099, 3, 1), ["funnel.ingested"])
    assert rows == [MetricRow(date(2099, 3, 1), "funnel.ingested", "", 587.0)]
    client, _ = make_app(metrics=reader)
    doc = body(client.get("/v1/metrics/cost.json", params={"from": "2099-02", "to": "2099-03"}))
    assert doc["months"][0]["cost_eur"] == 2.75
    assert statements and all(s.lstrip().upper().startswith("SELECT") for s in statements)


# -- solo lectura --------------------------------------------------------------------------------


def test_public_routes_are_get_only(client, pub):
    for route in client.app.routes:
        path = getattr(route, "path", "")
        if path.startswith("/admin"):
            continue
        assert set(route.methods) <= {"GET", "HEAD"}, path
    for path in public_paths(pub)[:6] + ["/v1/vulns/VS-CVE-2099-1001.json", "/nada"]:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            resp = client.request(method, path)
            assert resp.status_code == 405, (method, path)
            assert resp.headers["Allow"] == "GET"
            assert resp.headers["X-VS-Schema"] == "1.0.0"


def test_requests_do_not_change_the_publisher(pub):
    client, _ = make_app(publisher=pub)
    before = (
        [e.to_json() for e in pub.logs["all"].entries()],
        [e.to_json() for e in pub.logs["alerts"].entries()],
        {i: pub.vuln(i).body for i in {e.id for e in pub.logs["all"].entries()}},
        pub.stats.published,
    )
    for path in public_paths(pub):
        client.get(path)
    after = (
        [e.to_json() for e in pub.logs["all"].entries()],
        [e.to_json() for e in pub.logs["alerts"].entries()],
        {i: pub.vuln(i).body for i in {e.id for e in pub.logs["all"].entries()}},
        pub.stats.published,
    )
    assert before == after


def test_no_docs_or_openapi_exposed(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


# -- /admin --------------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["GET", "POST", "DELETE"])
def test_admin_without_jwt_is_401(client, method):
    for path in ("/admin", "/admin/queue", "/admin/verdict/1"):
        resp = client.request(method, path)
        assert resp.status_code == 401, (method, path)
        assert resp.headers["Cache-Control"] == "no-store"


def test_admin_with_bad_jwt_is_403(client):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    bad = [
        "basura",
        "a.b.c",
        access_jwt(key=other),
        access_jwt(kid="otro"),
        access_jwt(alg="HS256"),
        access_jwt(aud=["otra-app"]),
        access_jwt(iss="https://otro.example.invalid"),
        access_jwt(exp=now - 3600),
        access_jwt(nbf=now + 3600),
        access_jwt()[:-4] + "AAAA",
    ]
    for token in bad:
        resp = client.get("/admin/queue", headers={HEADER: token})
        assert resp.status_code == 403, token


def test_admin_with_valid_jwt_is_skeleton(client):
    resp = client.get("/admin/queue", headers={HEADER: access_jwt()})
    assert resp.status_code == 501
    assert body(resp)["error"] == "not_implemented"
    single_aud = access_jwt(aud=AUD)
    assert client.post("/admin/queue", headers={HEADER: single_aud}).status_code == 501


def test_admin_fail_closed_without_access_config(pub):
    client, _ = make_app(publisher=pub, access=AccessConfig())
    assert client.get("/admin/queue", headers={HEADER: access_jwt()}).status_code == 403


def test_access_config_requires_https():
    with pytest.raises(ValueError):
        AccessConfig("http://team.example.invalid", AUD)
    with pytest.raises(ValueError):
        AccessConfig("https://team.example.invalid/path", AUD)


# -- derechos (ADR-0022) -------------------------------------------------------------------------


def test_public_api_never_serves_restricted_data(client, pub):
    for path in public_paths(pub):
        text = client.get(path).text
        for marker in RESTRICTED_MARKERS:
            assert marker not in text, (path, marker)
    # Su único A sale de una fuente restricted: en la API pública no es A.
    record = body(client.get(f"/v1/vulns/{alert_id(CVE_RESTRICTED)}.json"))
    assert record["database_specific"]["vuln_sentinel"]["level"] != "A"


def test_api_refuses_a_publisher_with_restricted_audience():
    signer = LocalDevSigner.generate(CONFIG.key_id)
    clients_pub = FeedPublisher(CLIENTS, CONFIG, signer, LISTS)
    with pytest.raises(ApiConfigError):
        create_app(ApiConfig(INSTANCE, clients_pub, MemoryMetricsReader()))
    other = Audience("otra", frozenset({LicenseClass.OPEN}))
    with pytest.raises(ApiConfigError):
        create_app(ApiConfig(INSTANCE, FeedPublisher(other, CONFIG, signer, LISTS),
                             MemoryMetricsReader()))  # fmt: skip


def test_api_has_no_hardcoded_hosts():
    for path in (ROOT / "src" / "vs" / "api").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "example.org" not in text and "https://api." not in text, path
