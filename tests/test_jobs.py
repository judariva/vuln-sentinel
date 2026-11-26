"""Prueba de humo de los puntos de entrada (T13): ingest → publish → daily → API, con fixtures.

Necesita PostgreSQL (`VS_TEST_DATABASE_URL`, como `tests/test_db.py`): crea una base de datos
desechable, aplica las migraciones y ejecuta los jobs de verdad, con un transporte falso que sirve
los fixtures de cvelistV5 y CISA KEV. Sin red.

Escenario:
1. Carga inicial: dos CVE de cvelistV5 y el KEV del fixture (una CVE conocida y dos desconocidas).
   No alerta nada.
2. Repetir la misma ingesta no guarda nada (idempotencia).
3. Segundo ciclo: cvelistV5 trae una CVE que ya estaba en KEV desde la carga inicial (no alerta) y
   KEV añade dos CVE: una conocida y otra que no está en la base de datos y se pide a cvelistV5.
   Las dos salen en A.
"""

import copy
import json
import os
import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from tests.fakes import FakeTransport, fixture_bytes, ok
from vs.feed.sign import jwks, verify_detached
from vs.jobs import daily, ingest, investigate, publish
from vs.jobs.settings import ROOT, Settings, run_main
from vs.model.migrate import normalize_url, upgrade
from vs.sources import cisa_kev, cvelistv5

URL = os.environ.get("VS_TEST_DATABASE_URL")

T1 = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)
T2 = T1 + timedelta(minutes=5)
T3 = T2 + timedelta(minutes=5)
BASE = cvelistv5.DEFAULT_RECORD_BASE_URL
KNOWN_IN_KEV = "CVE-2026-103406"  # en cvelistV5 y en el KEV de la carga inicial
LATE_KEV = "CVE-2026-133469"  # en el KEV de la carga inicial; llega a cvelistV5 después
NEW_KEV_KNOWN = "CVE-2026-131916"  # en cvelistV5; entra en KEV en el segundo ciclo
NEW_KEV_UNKNOWN = "CVE-2026-140001"  # no está en la base de datos; se pide a cvelistV5


@pytest.fixture(scope="module")
def db_url():
    if not URL:
        pytest.skip("sin VS_TEST_DATABASE_URL")
    admin_url = make_url(normalize_url(URL))
    name = f"vs_test_{uuid.uuid4().hex[:12]}"
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = admin_url.set(database=name).render_as_string(hide_password=False)
    try:
        upgrade(url)
        yield url
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def settings(tmp: Path, url: str | None, dist: Path | None = None) -> Settings:
    instance = tmp / "instance.yaml"
    instance.write_text(
        "instance:\n  name: public\n  kind: public\n  allowed_license_classes: [open]\n"
        "  connectors:\n    - name: cvelistv5\n    - name: cisa_kev\n",
        encoding="utf-8",
    )
    return Settings(
        database_url=url,
        config_dir=ROOT / "config",
        instance_path=instance,
        brand_path=ROOT / "config" / "brand.example.yaml",
        signing_key=tmp / "signing" / "dev.pem",
        feed_dir=tmp / "feed",
        web_dist=dist,
        connectors=None,
        agent_enabled=False,
    )


def cve_url(cve: str) -> str:
    return ingest.cve_record_url(BASE, cve)


def cve_body(cve: str) -> bytes:
    """Registro de cvelistV5 del fixture con otro identificador."""
    doc = json.loads(fixture_bytes("cvelistv5", "CVE-2026-131916.json"))
    doc["cveMetadata"]["cveId"] = cve
    return json.dumps(doc).encode()


def kev_body(extra: list[str]) -> bytes:
    doc = json.loads(fixture_bytes("cisa-kev", "kev.json"))
    template = doc["vulnerabilities"][0]
    for cve in extra:
        item = copy.deepcopy(template)
        item.update(cveID=cve, dateAdded="2026-11-26")
        doc["vulnerabilities"].append(item)
    doc["dateReleased"] = "2026-11-26T09:01:00.000Z"
    doc["catalogVersion"] = "2026.11.26"
    doc["count"] = len(doc["vulnerabilities"])
    return json.dumps(doc).encode()


def delta_body(when: str, updated: list[str]) -> bytes:
    log = json.loads(fixture_bytes("cvelistv5", "deltaLog.json"))
    items = [{"cveId": c, "githubLink": cve_url(c)} for c in updated]
    log.insert(0, {"fetchTime": when, "new": [], "updated": items})
    return json.dumps(log).encode()


def transport(cycle: int) -> FakeTransport:
    routes = {
        cvelistv5.DEFAULT_DELTA_LOG_URL: ok(fixture_bytes("cvelistv5", "deltaLog.json")),
        cve_url("CVE-2026-131916"): ok(fixture_bytes("cvelistv5", "CVE-2026-131916.json")),
        cve_url(KNOWN_IN_KEV): ok(fixture_bytes("cvelistv5", "CVE-2026-103406.json")),
        cisa_kev.DEFAULT_URL: ok(fixture_bytes("cisa-kev", "kev.json")),
    }
    if cycle >= 2:
        routes[cvelistv5.DEFAULT_DELTA_LOG_URL] = ok(
            delta_body("2026-11-26T09:03:00.000Z", [LATE_KEV])
        )
        routes[cve_url(LATE_KEV)] = ok(cve_body(LATE_KEV))
        routes[cve_url(NEW_KEV_UNKNOWN)] = ok(cve_body(NEW_KEV_UNKNOWN))
        routes[cisa_kev.DEFAULT_URL] = ok(kev_body([NEW_KEV_KNOWN, NEW_KEV_UNKNOWN]))
    return FakeTransport(routes)


def rows(url: str, sql: str, **params) -> list:
    engine = create_engine(normalize_url(url))
    try:
        with engine.connect() as conn:
            return list(conn.execute(text(sql), params).all())
    finally:
        engine.dispose()


def scalar(url: str, sql: str, **params):
    found = rows(url, sql, **params)
    return found[0][0] if found else None


@pytest.mark.db
def test_entrypoints_end_to_end(db_url, tmp_path):
    s = settings(tmp_path, db_url)

    # 1. Carga inicial: nada alerta.
    assert ingest.run(s, transport=transport(1), clock=lambda: T1) == 0
    assert scalar(db_url, "SELECT count(*) FROM vulnerability") == 2
    assert scalar(db_url, "SELECT count(*) FROM alert") == 0
    assert scalar(db_url, "SELECT count(*) FROM source WHERE baseline_completed_at IS NULL") == 0
    # Las dos CVE del KEV que aún no conocemos quedan anotadas, sin guardar.
    assert scalar(db_url, "SELECT count(*) FROM fact_seen WHERE NOT stored") == 2
    assert scalar(db_url, "SELECT count(*) FROM signal WHERE kind = 'kev_cisa'") == 1

    assert publish.run(s, clock=lambda: T1 + timedelta(minutes=1)) == 0
    assert scalar(db_url, "SELECT count(*) FROM feed_record") == 2
    assert scalar(db_url, "SELECT count(*) FROM feed_record WHERE level <> 'none'") == 0

    # 2. Idempotente: la misma ingesta no guarda nada nuevo.
    counts = scalar(
        db_url, "SELECT (SELECT count(*) FROM signal) + (SELECT count(*) FROM fact_seen)"
    )
    assert ingest.run(s, transport=transport(1), clock=lambda: T1 + timedelta(minutes=2)) == 0
    assert (
        scalar(db_url, "SELECT (SELECT count(*) FROM signal) + (SELECT count(*) FROM fact_seen)")
        == counts
    )
    assert publish.run(s, clock=lambda: T1 + timedelta(minutes=3)) == 0

    # 3. Segundo ciclo.
    assert ingest.run(s, transport=transport(2), clock=lambda: T2) == 0
    alerts = dict(rows(db_url, "SELECT cve_id, level FROM alert"))
    assert alerts == {NEW_KEV_KNOWN: "A", NEW_KEV_UNKNOWN: "A"}
    # Un catálogo KEV nuevo no vuelve a guardar las entradas que ya tenía.
    assert (
        scalar(
            db_url,
            "SELECT count(*) FROM signal WHERE kind = 'kev_cisa' AND cve_id = :cve",
            cve=KNOWN_IN_KEV,
        )
        == 1
    )
    # La señal KEV de la carga inicial se guarda al llegar su CVE, sin perder su marca.
    late = rows(db_url, "SELECT kind, baseline FROM signal WHERE cve_id = :cve", cve=LATE_KEV)
    assert ("kev_cisa", True) in [tuple(r) for r in late]

    assert publish.run(s, clock=lambda: T3) == 0
    feed = tmp_path / "feed"
    latest = json.loads((feed / "v1/feed/alerts/latest.json").read_bytes())
    assert {a["id"] for a in latest["alerts"]} == {
        f"VS-{NEW_KEV_KNOWN}",
        f"VS-{NEW_KEV_UNKNOWN}",
    }
    # Firma detached válida con el JWKS publicado.
    keys = json.loads((feed / ".well-known/vuln-sentinel/keys.json").read_bytes())
    body = (feed / f"v1/vulns/VS-{NEW_KEV_KNOWN}.json").read_bytes()
    jws = (feed / f"v1/vulns/VS-{NEW_KEV_KNOWN}.json.jws").read_text()
    assert verify_detached(jws, body, keys) == keys["keys"][0]["kid"]

    # Métricas del día.
    assert daily.run(s, ["2026-11-26"]) == 0
    assert (
        scalar(
            db_url,
            "SELECT value FROM metric_daily WHERE day = '2026-11-26'"
            " AND metric = 'funnel.alerted' AND dimension = 'A'",
        )
        == 2
    )

    # Investigación: apagada por defecto.
    assert investigate.run(s) == 0

    # API sobre PostgreSQL, con el portal en el mismo origen.
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>portal</title>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    from vs.api.serve import build_app

    with TestClient(build_app(settings(tmp_path, db_url, dist))) as client:
        r = client.get("/v1/feed/alerts/latest.json")
        assert r.status_code == 200
        assert len(r.json()["alerts"]) == 2
        r = client.get(f"/v1/vulns/VS-{NEW_KEV_KNOWN}.json")
        assert r.status_code == 200 and r.content == body
        jws_api = client.get(f"/v1/vulns/VS-{NEW_KEV_KNOWN}.json.jws").text
        api_keys = client.get("/.well-known/vuln-sentinel/keys.json").json()
        assert verify_detached(jws_api, r.content, api_keys)
        head = client.get("/v1/feed/all/changes").json()
        assert {s["name"] for s in head["sources"]} == {"cvelistv5", "cisa_kev"}
        assert len(head["entries"]) >= 4
        metrics = client.get("/v1/metrics/daily.json?from=2026-11-26&to=2026-11-26").json()
        assert any(m["metric"] == "funnel.alerted" for m in metrics["rows"])
        assert client.get("/").text.startswith("<!doctype html>")
        assert client.get("/alertas/VS-CVE-2026-131916").text.startswith("<!doctype html>")
        assert client.get("/assets/app.js").headers["cache-control"].startswith("public")
        assert client.get("/v1/no-existe").status_code == 404
        assert client.post("/v1/feed/alerts/latest.json").status_code == 405


def test_jobs_fail_without_database(tmp_path, monkeypatch):
    """Sin VS_DATABASE_URL cada job sale con 2 (configuración), nunca con 0."""
    monkeypatch.delenv("VS_DATABASE_URL", raising=False)
    s = settings(tmp_path, None)
    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls, env=None: s))
    for job in (ingest, publish, daily):
        assert run_main(job.main) == 2, job.__name__


def test_investigate_disabled_needs_no_database(tmp_path):
    assert investigate.run(settings(tmp_path, None)) == 0


def test_settings_from_env(tmp_path):
    s = Settings.from_env(
        {
            "VS_DATABASE_URL": "postgresql://u@h/db",
            "VS_CONNECTORS": "cvelistv5, cisa_kev",
            "VS_AGENT_ENABLED": "1",
            "VS_FEED_DIR": str(tmp_path),
        }
    )
    assert s.connectors == {"cvelistv5", "cisa_kev"}
    assert s.agent_enabled and s.feed_dir == tmp_path
    assert Settings.from_env({}).connectors is None
    assert not Settings.from_env({}).agent_enabled


def test_cve_record_url():
    assert ingest.cve_record_url(BASE, "CVE-2024-21762") == BASE + "2024/21xxx/CVE-2024-21762.json"
    assert ingest.cve_record_url(BASE, "CVE-2021-0001") == BASE + "2021/0xxx/CVE-2021-0001.json"


def test_dir_writer_stays_inside(tmp_path):
    from vs.feed.publish import Document

    w = publish.DirWriter(tmp_path)
    w.put(Document("/v1/x.json", b"{}", {}))
    assert (tmp_path / "v1" / "x.json").read_bytes() == b"{}"
    with pytest.raises(ValueError):
        w.put(Document("/../fuera.json", b"{}", {}))


def test_daily_args():
    today = date(2026, 11, 26)
    assert daily.days_from_args([], today) == [date(2026, 11, 25), today]
    assert daily.days_from_args(["2026-11-01"], today) == [date(2026, 11, 1)]


def test_keys_document_has_no_private_material(tmp_path):
    """La clave de desarrollo vive fuera del repo en el test y el JWKS no lleva parte privada."""
    s = settings(tmp_path, None)
    signer = s.signer(s.feed_config())
    doc = jwks([signer])
    assert "d" not in doc["keys"][0]
