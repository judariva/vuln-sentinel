"""El montaje de la prueba de humo del portal (T8a) da lo que las pantallas necesitan.

Si este test falla, la prueba de humo de Playwright también: aquí se ve antes y sin navegador.
"""

from __future__ import annotations

import json
from collections import Counter
from urllib.parse import quote

from fastapi.testclient import TestClient

from tests.portal_fixture import (
    CVE_B,
    CVE_C,
    NOW,
    VOLUME_LEVELS,
    VOLUME_SHOTS,
    compressible,
    is_api,
    make_app,
    volume_batches,
    volume_cve,
)
from tests.test_feed import CVE_EXPOSED
from vs.feed.osv import alert_id

# Partículas del día en el montaje base: 1001 (A), 1002 (none), 1003 (none en público), 1004 (C)
# y 1005 (B).
BASE_TODAY = 5


def all_changes_today(client: TestClient) -> dict[str, str]:
    """CVE con cambios hoy en el feed completo → nivel de su último cambio (como el embudo)."""
    last: dict[str, dict] = {}
    since = None
    generated = ""
    for _ in range(50):
        page = json.loads(
            client.get("/v1/feed/all/changes" + (f"?since={quote(since)}" if since else "")).content
        )
        generated = generated or page["generated_at"]
        for e in page["entries"]:
            if e["modified"].startswith(generated[:10]):
                prev = last.get(e["id"])
                if prev is None or e["modified"] >= prev["modified"]:
                    last[e["id"]] = e
        if not page["has_more"] or not page["next"]:
            break
        since = page["next"]
    else:
        raise AssertionError("el feed no termina")
    return {k: v["level"] for k, v in last.items()}


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


# -- volumen (T8c): el embudo y las capturas con un día realista --------------------------------


def test_volume_batches_are_deterministic_and_inside_the_day():
    a, b = volume_batches(VOLUME_SHOTS), volume_batches(VOLUME_SHOTS)
    assert list(a) == list(b)
    assert [[(r.cve_id, r.kind) for r in a[t]] for t in a] == [
        [(r.cve_id, r.kind) for r in b[t]] for t in b
    ]
    assert all(t.date() == NOW.date() and t < NOW for t in a)
    assert len(a) > 10  # repartidas en el día, no en una sola tanda
    cves = {r.cve_id for recs in a.values() for r in recs}
    assert cves == {volume_cve(i) for i in range(VOLUME_SHOTS)}
    assert all(c.startswith("CVE-2099-") for c in cves)


def test_volume_fixture_has_hundreds_of_changes_and_few_alerts():
    client = TestClient(make_app(VOLUME_SHOTS))
    today = all_changes_today(client)
    assert len(today) == BASE_TODAY + VOLUME_SHOTS
    assert all(k.startswith("VS-CVE-2099-") for k in today)

    latest = json.loads(client.get("/v1/feed/alerts/latest.json").content)
    levels = {a["id"]: a["level"] for a in latest["alerts"]}
    want = {alert_id(volume_cve(i)): lv for i, lv in VOLUME_LEVELS.items()}
    want |= {alert_id(CVE_EXPOSED): "A", alert_id(CVE_B): "B", alert_id(CVE_C): "C"}
    assert levels == want
    assert Counter(levels.values()) == {"A": 3, "B": 5, "C": 6}
    # El resto del día no es alerta: el polvo del embudo.
    assert sum(lv == "none" for lv in today.values()) == len(today) - len(levels)


def test_volume_zero_is_the_base_fixture():
    assert len(all_changes_today(TestClient(make_app(0)))) == BASE_TODAY
