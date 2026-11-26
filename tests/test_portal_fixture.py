"""El montaje de la prueba de humo del portal (T8a) da lo que las pantallas necesitan.

Si este test falla, la prueba de humo de Playwright también: aquí se ve antes y sin navegador.
"""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from tests.portal_fixture import CVE_B, CVE_C, compressible, is_api, make_app
from tests.test_feed import CVE_EXPOSED
from vs.feed.osv import alert_id


def test_fixture_has_one_alert_per_level_today():
    client = TestClient(make_app())
    latest = json.loads(client.get("/v1/feed/alerts/latest.json").content)
    levels = {a["id"]: a["level"] for a in latest["alerts"]}
    assert levels == {alert_id(CVE_EXPOSED): "A", alert_id(CVE_B): "B", alert_id(CVE_C): "C"}
    changes = json.loads(client.get("/v1/feed/alerts/changes").content)
    assert all(e["modified"].startswith("2099-03-01") for e in changes["entries"])
    assert changes["generated_at"].startswith("2099-03-01")


def test_fixture_metrics_and_cost_without_donations():
    client = TestClient(make_app())
    daily = json.loads(client.get("/v1/metrics/daily.json").content)
    names = {r["metric"] for r in daily["rows"]}
    assert {"funnel.ingested", "detection.p50_minutes", "kev_lead.p50_minutes"} <= names
    cost = client.get("/v1/metrics/cost.json")
    assert cost.status_code == 200 and b"donation" not in cost.content


def test_fixture_admin_is_closed():
    client = TestClient(make_app())
    # Sin Access configurado, /admin cierra con 403 (T6).
    assert client.get("/admin").status_code == 403


def test_fixture_routes_api_by_segment():
    # `/admin` y `/admin/...` son de la API; las rutas del portal, aunque empiecen igual, no.
    assert is_api("/admin") and is_api("/admin/") and is_api("/admin/x?y=1")
    assert is_api("/v1/feed/alerts/latest.json") and is_api("/.well-known/x")
    assert not is_api("/administracion") and not is_api("/gestion") and not is_api("/v1x")


def test_fixture_compresses_text_like_the_edge():
    # T8b: Lighthouse mide la red; el JS, el CSS y el JSON van con gzip como en producción.
    for ctype in (
        "text/javascript",
        "application/javascript",
        "text/css",
        "text/html",
        "application/json",
    ):
        assert compressible(ctype)
    for ctype in ("image/png", "application/octet-stream", "application/jose"):
        assert not compressible(ctype)
