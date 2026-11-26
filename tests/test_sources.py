"""Conectores abiertos (T3): normalización, `source_run`, carga inicial y fail-closed.

Sin red: cada test monta un `FakeTransport` con los fixtures de `tests/fixtures/` (ver su README).
"""

from __future__ import annotations

import gzip
import json
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.fakes import FakeTransport, fixture_bytes, ok
from vs.instance import load_instance
from vs.model import schema
from vs.sources import (
    BUILTIN,
    cisa_kev,
    cvelistv5,
    epss,
    exploitdb,
    ghsa,
    github_search,
    metasploit,
    nomisec,
    osv,
)
from vs.sources.base import (
    ENTITY_COLUMNS,
    REGISTRY,
    Connector,
    Entity,
    LicenseClass,
    Record,
)
from vs.sources.http import Response
from vs.sources.osv import OsvPolicy, policy_for
from vs.sources.run import RunStatus, SourceRunResult, run_source

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 26, 9, 0, tzinfo=UTC)
TABLES = {
    Entity.VULNERABILITY: schema.Vulnerability.__table__,
    Entity.AFFECTED_PRODUCT: schema.AffectedProduct.__table__,
    Entity.SIGNAL: schema.Signal.__table__,
}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Cualquier intento de red real hace fallar el test."""

    def boom(*_a, **_k):
        raise AssertionError("llamada de red real en un test")

    monkeypatch.setattr(urllib.request, "urlopen", boom)


def at(when: datetime) -> Callable[[], datetime]:
    return lambda: when


def run(conn: Connector, *, now: datetime = NOW, **kwargs) -> SourceRunResult:
    return run_source(conn, clock=at(now), **kwargs)


# -- montaje de cada conector con sus fixtures ---------------------------------------------------

CVE_BASE = cvelistv5.DEFAULT_RECORD_BASE_URL
CVE_131916 = CVE_BASE + "2026/131xxx/CVE-2026-131916.json"
CVE_103406 = CVE_BASE + "2026/103xxx/CVE-2026-103406.json"
GHSA_PAGE1 = ghsa.DEFAULT_API_URL + "?type=reviewed&sort=updated&direction=desc&per_page=100"
GHSA_PAGE2 = GHSA_PAGE1 + "&page=2"
OSV_BASE = osv.DEFAULT_RECORD_BASE_URL


@dataclass
class Setup:
    connector: Connector
    transport: FakeTransport
    main_url: str  # la primera URL que pide el conector
    record_url: str | None = None  # una URL secundaria (registro individual), si la hay


def kev_setup(config=None) -> Setup:
    t = FakeTransport({cisa_kev.DEFAULT_URL: ok(fixture_bytes("cisa-kev", "kev.json"))})
    return Setup(cisa_kev.CisaKevConnector(config, transport=t), t, cisa_kev.DEFAULT_URL)


def epss_setup(config=None) -> Setup:
    body = gzip.compress(fixture_bytes("epss", "epss_scores.csv"))
    t = FakeTransport({epss.DEFAULT_URL: ok(body)})
    return Setup(epss.EpssConnector(config, transport=t), t, epss.DEFAULT_URL)


def cve_setup(config=None) -> Setup:
    t = FakeTransport(
        {
            cvelistv5.DEFAULT_DELTA_LOG_URL: ok(fixture_bytes("cvelistv5", "deltaLog.json")),
            CVE_131916: ok(fixture_bytes("cvelistv5", "CVE-2026-131916.json")),
            CVE_103406: ok(fixture_bytes("cvelistv5", "CVE-2026-103406.json")),
        }
    )
    conn = cvelistv5.CveListV5Connector(config, transport=t)
    return Setup(conn, t, cvelistv5.DEFAULT_DELTA_LOG_URL, CVE_103406)


def ghsa_setup(config=None) -> Setup:
    link = f'<{GHSA_PAGE2}>; rel="next", <{GHSA_PAGE2}>; rel="last"'
    t = FakeTransport(
        {
            GHSA_PAGE1: ok(fixture_bytes("ghsa", "page1.json"), headers={"Link": link}),
            GHSA_PAGE2: ok(fixture_bytes("ghsa", "page2.json")),
        }
    )
    return Setup(ghsa.GhsaConnector(config, transport=t), t, GHSA_PAGE1, GHSA_PAGE2)


def osv_setup(config=None, modified: Response | None = None) -> Setup:
    t = FakeTransport(
        {
            osv.DEFAULT_MODIFIED_URL: modified or ok(fixture_bytes("osv", "modified_id.csv")),
            OSV_BASE + "Alpine/ALPINE-CVE-2099-0001.json": ok(
                fixture_bytes("osv", "Alpine", "ALPINE-CVE-2099-0001.json")
            ),
            OSV_BASE + "crates.io/RUSTSEC-2021-0003.json": ok(
                fixture_bytes("osv", "crates.io", "RUSTSEC-2021-0003.json")
            ),
            OSV_BASE + "npm/GHSA-0000-0000-0001.json": ok(
                fixture_bytes("osv", "npm", "GHSA-0000-0000-0001.json")
            ),
        }
    )
    conn = osv.OsvConnector(config, transport=t)
    return Setup(conn, t, osv.DEFAULT_MODIFIED_URL, OSV_BASE + "crates.io/RUSTSEC-2021-0003.json")


def msf_setup(config=None) -> Setup:
    body = fixture_bytes("metasploit", "modules_metadata_base.json")
    t = FakeTransport({metasploit.DEFAULT_URL: ok(body)})
    return Setup(metasploit.MetasploitConnector(config, transport=t), t, metasploit.DEFAULT_URL)


def edb_setup(config=None) -> Setup:
    body = fixture_bytes("exploitdb", "files_exploits.csv")
    t = FakeTransport({exploitdb.DEFAULT_URL: ok(body)})
    return Setup(exploitdb.ExploitDbConnector(config, transport=t), t, exploitdb.DEFAULT_URL)


NOMI_API = nomisec.DEFAULT_API_URL
NOMI_RAW = nomisec.DEFAULT_RAW_BASE_URL
SHA_A, SHA_B = "a" * 40, "b" * 40
NOMI_COMMITS = NOMI_API + "/commits?per_page=100"
NOMI_FILE_A = NOMI_RAW + SHA_A + "/2099/CVE-2099-0301.json"
NOMI_FILE_B = NOMI_RAW + SHA_B + "/2018/CVE-2018-3260.json"


def nomi_setup(config=None) -> Setup:
    t = FakeTransport(
        {
            NOMI_COMMITS: ok(fixture_bytes("nomisec", "commits.json")),
            NOMI_API + "/commits/" + SHA_A: ok(fixture_bytes("nomisec", "commit-a.json")),
            NOMI_API + "/commits/" + SHA_B: ok(fixture_bytes("nomisec", "commit-b.json")),
            NOMI_FILE_A: ok(fixture_bytes("nomisec", "CVE-2099-0301.json")),
            NOMI_FILE_B: ok(fixture_bytes("nomisec", "CVE-2018-3260.json")),
        }
    )
    conn = nomisec.NomiSecConnector(config, transport=t)
    return Setup(conn, t, NOMI_COMMITS, NOMI_FILE_B)


SEARCH_CVE = "CVE-2099-0401"
SEARCH_URL = (
    github_search.DEFAULT_API_URL
    + "/search/repositories?q=%22CVE-2099-0401%22+in%3Aname%2Cdescription%2Creadme"
    + "&sort=updated&order=desc&per_page=30"
)
# La búsqueda es en vivo: la respuesta del fixture es de 10 minutos antes de NOW.
SEARCH_DATE = "Thu, 26 Nov 2026 08:50:00 GMT"


def search_items(*repos: tuple[str, bool]) -> bytes:
    items = [
        {
            "id": 990000500 + i,
            "full_name": name,
            "owner": {"login": name.split("/")[0]},
            "html_url": "https://github.com/" + name,
            "fork": fork,
            "created_at": "2026-11-25T10:00:00Z",
        }
        for i, (name, fork) in enumerate(repos)
    ]
    body = {"total_count": len(items), "incomplete_results": False, "items": items}
    return json.dumps(body).encode()


def search_setup(config=None) -> Setup:
    body = search_items(("example-research/CVE-2099-0401", False))
    t = FakeTransport({SEARCH_URL: ok(body, headers={"Date": SEARCH_DATE})})
    cfg = {"candidates": [SEARCH_CVE], **(config or {})}
    conn = github_search.GithubSearchConnector(cfg, transport=t, limiter=NoWaitLimiter())
    return Setup(conn, t, SEARCH_URL)


class NoWaitLimiter:
    """Limitador de los tests: cuenta las peticiones y no espera."""

    def __init__(self) -> None:
        self.calls = 0

    def acquire(self) -> None:
        self.calls += 1


SETUPS: dict[str, Callable[..., Setup]] = {
    "cisa_kev": kev_setup,
    "epss": epss_setup,
    "cvelistv5": cve_setup,
    "ghsa": ghsa_setup,
    "osv": osv_setup,
    "metasploit": msf_setup,
    "exploitdb": edb_setup,
    "nomisec": nomi_setup,
    "github_search": search_setup,
}


# -- registro y licencias --------------------------------------------------------------------------


def test_builtin_connectors_are_registered_and_open():
    assert set(BUILTIN) == set(SETUPS)
    for name in BUILTIN:
        cls = REGISTRY.get(name)
        assert cls.license_class is LicenseClass.OPEN
        assert cls.licensee is None
        assert cls.freshness_threshold is not None


def test_euvd_has_no_connector():
    """La licencia de la EUVD sigue SIN VERIFICAR: no hay conector (decisión de Juan, T3)."""
    assert not any("euvd" in n for n in REGISTRY.names())


def test_public_instance_builds_the_open_connectors():
    inst = load_instance(ROOT / "config" / "instance.public.yaml")
    built = inst.build_connectors()
    assert sorted(c.name for c in built) == sorted(BUILTIN)


# -- modelo: filas compatibles con T2 ------------------------------------------------------------


def test_entity_columns_exist_in_the_model():
    for entity, cols in ENTITY_COLUMNS.items():
        missing = cols - set(TABLES[entity].columns.keys())
        assert not missing, f"{entity}: columnas que no están en el modelo: {missing}"


def test_source_run_row_matches_the_model():
    res = run(kev_setup().connector)
    cols = set(schema.SourceRun.__table__.columns.keys()) - {"id"}
    assert set(res.to_row()) == cols


def test_record_rejects_unknown_columns():
    with pytest.raises(ValueError, match="columnas no válidas"):
        Record(
            "x",
            "CVE-2099-0001",
            "v",
            LicenseClass.OPEN,
            value={"nope": 1},
            entity=Entity.VULNERABILITY,
        )
    with pytest.raises(ValueError, match="columnas no válidas"):
        Record(
            "x",
            "CVE-2099-0001",
            "v",
            LicenseClass.OPEN,
            value={"baseline": True},
            entity=Entity.VULNERABILITY,
        )


def test_record_to_row_needs_the_runner():
    rec = Record("x", "CVE-2099-0001", "epss", LicenseClass.OPEN)
    with pytest.raises(ValueError, match="observed_at"):
        rec.to_row()


@pytest.mark.parametrize("name", sorted(SETUPS))
def test_rows_fit_the_model(name):
    res = run(SETUPS[name]().connector)
    assert res.status is RunStatus.OK, res.error
    assert res.records
    for rec in res.records:
        row = rec.to_row()
        table = TABLES[rec.entity]
        assert set(row) <= set(table.columns.keys())
        assert row["observed_at"] == NOW
        assert row["license_class"] is LicenseClass.OPEN and row["licensee"] is None
        if rec.entity is not Entity.SIGNAL:
            assert row["source_published_at"] is not None  # NOT NULL en el modelo
        json.dumps(row.get("value", {}), default=str)


# -- carga inicial (ADR-0012) y source_run -------------------------------------------------------


@pytest.mark.parametrize("name", sorted(SETUPS))
def test_first_run_is_baseline(name):
    res = run(SETUPS[name]().connector)
    assert res.status is RunStatus.OK, res.error
    assert res.baseline and res.baseline_completed
    assert all(r.baseline for r in res.records)
    assert all(r.observed_at == NOW for r in res.records)
    assert res.items_seen == len(res.records) == res.items_new


@pytest.mark.parametrize("name", sorted(SETUPS))
def test_run_after_baseline_is_not_baseline(name):
    res = run(SETUPS[name]().connector, baseline_completed_at=NOW - timedelta(days=1))
    assert res.status is RunStatus.OK, res.error
    assert not res.baseline and not res.baseline_completed
    assert not any(r.baseline for r in res.records)


def test_items_new_counts_unseen_records():
    first = run(kev_setup().connector)
    known = {first.records[0].key()}
    again = run(kev_setup().connector, seen=lambda r: r.key() in known)
    assert again.items_seen == 3 and again.items_new == 2


# -- fail-closed: un test por caso de fallo y por conector -------------------------------------


def _assert_unknown(res: SourceRunResult, needle: str) -> None:
    assert res.status is RunStatus.UNKNOWN
    assert res.records == ()
    assert res.items_seen == 0 and res.items_new == 0
    assert not res.baseline_completed
    assert res.error and needle.lower() in res.error.lower(), res.error
    assert res.to_row()["status"] == "unknown"


@pytest.mark.parametrize("name", sorted(SETUPS))
def test_timeout_is_unknown(name):
    s = SETUPS[name]()
    s.transport.routes[s.main_url] = TimeoutError("timed out")
    _assert_unknown(run(s.connector), "timeout")


@pytest.mark.parametrize("name", sorted(SETUPS))
def test_http_500_is_unknown(name):
    s = SETUPS[name]()
    s.transport.routes[s.main_url] = ok(b"oops", status=500)
    _assert_unknown(run(s.connector), "HTTP 500")


BROKEN = {
    "cisa_kev": b'{"vulnerabilities": [',
    "epss": b"esto no es el CSV de EPSS\n",
    "cvelistv5": b"[{]",
    "ghsa": b"[{]",
    "osv": b"no-es-una-fecha,sin-barra\n",
    "metasploit": b'{"m": {"fullname": "exploit/x", "mod_time": "ayer"}}',
    "exploitdb": b"esto,no,es,el,CSV\n1,2,3,4,5\n",
    "nomisec": b'[{"sha": "no-es-un-sha"}]',
    "github_search": b'{"total_count": 1}',
}


@pytest.mark.parametrize("name", sorted(SETUPS))
def test_broken_payload_is_unknown(name):
    s = SETUPS[name]()
    s.transport.routes[s.main_url] = ok(BROKEN[name])
    _assert_unknown(run(s.connector), "SourceError")


@pytest.mark.parametrize("name", sorted(SETUPS))
def test_stale_data_is_unknown(name):
    s = SETUPS[name]()
    _assert_unknown(run(s.connector, now=NOW + timedelta(days=30)), "umbral")


@pytest.mark.parametrize("name", sorted(SETUPS))
def test_stale_threshold_is_configurable(name):
    # Con el umbral por defecto el dato vale; con 1 minuto ya no.
    assert run(SETUPS[name]().connector).status is RunStatus.OK
    _assert_unknown(run(SETUPS[name]({"freshness_hours": 1 / 60}).connector), "umbral")


@pytest.mark.parametrize("name", ["cvelistv5", "ghsa", "osv", "nomisec"])
def test_failure_in_a_later_request_drops_the_whole_run(name):
    """Si falla una petición secundaria, no se guarda media ejecución: UNKNOWN y nada más."""
    s = SETUPS[name]()
    assert s.record_url
    s.transport.routes[s.record_url] = ok(b"oops", status=503)
    _assert_unknown(run(s.connector), "HTTP 503")


# -- CISA KEV --------------------------------------------------------------------------------------


def test_kev_normalizes_signals():
    res = run(kev_setup().connector)
    assert res.data_as_of == datetime(2026, 11, 25, 19, 48, 12, 434400, tzinfo=UTC)
    assert [r.cve_id for r in res.records] == [
        "CVE-2026-103406",
        "CVE-2026-133469",
        "CVE-2025-41450",
    ]
    rec = res.records[0]
    assert rec.entity is Entity.SIGNAL and rec.kind == "kev_cisa"
    assert rec.source_published_at is None  # KEV solo da fecha (R4)
    assert rec.value["date_added"] == "2026-11-25"
    assert rec.value["catalog_version"] == "2026.11.25"
    assert rec.url.endswith("field_cve=CVE-2026-103406")
    assert res.last_item_published_at is None


def test_kev_count_mismatch_is_unknown():
    s = kev_setup()
    data = json.loads(fixture_bytes("cisa-kev", "kev.json"))
    data["count"] = 1805  # el catálogo dice más entradas de las que llegan: truncado
    s.transport.routes[s.main_url] = ok(json.dumps(data).encode())
    _assert_unknown(run(s.connector), "count")


def test_kev_bad_cve_is_unknown():
    s = kev_setup()
    data = json.loads(fixture_bytes("cisa-kev", "kev.json"))
    data["vulnerabilities"][1]["cveID"] = "CVE-NOPE"
    s.transport.routes[s.main_url] = ok(json.dumps(data).encode())
    _assert_unknown(run(s.connector), "cveID")


# -- EPSS ------------------------------------------------------------------------------------------


def test_epss_normalizes_signals():
    res = run(epss_setup().connector)
    score_date = datetime(2026, 11, 25, 12, 0, 23, tzinfo=UTC)
    assert res.data_as_of == score_date
    assert len(res.records) == 4
    rec = next(r for r in res.records if r.cve_id == "CVE-2026-103406")
    assert rec.kind == "epss"
    assert rec.value == {
        "epss": 0.0086,
        "percentile": 0.56019,
        "model_version": "v2026.06.15",
        "score_date": "2026-11-25",
    }
    assert rec.source_published_at == score_date


def test_epss_reads_uncompressed_csv_too():
    s = epss_setup()
    s.transport.routes[s.main_url] = ok(fixture_bytes("epss", "epss_scores.csv"))
    assert len(run(s.connector).records) == 4


def test_epss_out_of_range_is_unknown():
    s = epss_setup()
    text = fixture_bytes("epss", "epss_scores.csv").decode().replace("0.0086", "1.5")
    s.transport.routes[s.main_url] = ok(text.encode())
    _assert_unknown(run(s.connector), "fuera de [0, 1]")


# -- cvelistV5 -------------------------------------------------------------------------------------


def test_cvelist_baseline_normalizes_entities():
    res = run(cve_setup().connector)
    by = {(r.entity, r.cve_id, r.kind): r for r in res.records}
    assert len(res.records) == 5

    v1 = by[(Entity.VULNERABILITY, "CVE-2026-131916", "vulnerability")]
    assert v1.value["cna"] == "jpcert"
    assert v1.value["cvss_vector"].startswith("CVSS:4.0/")  # se prefiere la versión más nueva
    assert v1.value["cvss_source"] == "cna"
    assert v1.value["cwe"] == ["CWE-918"]
    assert v1.value["withdrawn_at"] is None
    assert v1.source_published_at == datetime(2026, 11, 26, 8, 15, 33, 720000, tzinfo=UTC)

    v2 = by[(Entity.VULNERABILITY, "CVE-2026-103406", "vulnerability")]
    assert v2.value["vendor"] == "Juniper Networks"
    assert v2.value["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    ap = by[(Entity.AFFECTED_PRODUCT, "CVE-2026-103406", "affected_product")]
    assert ap.value["range_source"] == "cna:juniper"
    rng = ap.value["ranges"][0]
    assert rng["type"] == "cve5" and rng["default_status"] == "unaffected"
    assert {"version": "7.1.0", "lessThan": "7.1.7"}.items() <= rng["versions"][1].items()

    ssvc = by[(Entity.SIGNAL, "CVE-2026-103406", "ssvc")]
    assert ssvc.value["exploitation"] == "active"
    assert ssvc.value["technical_impact"] == "total"
    assert ssvc.value["provider"] == "CISA-ADP"
    assert ssvc.source_published_at == datetime(2026, 11, 25, tzinfo=UTC)


def test_cvelist_incremental_reads_only_after_cursor():
    s = cve_setup()
    res = run(
        s.connector,
        since=datetime(2026, 11, 26, 6, 0, tzinfo=UTC),
        baseline_completed_at=NOW - timedelta(days=1),
    )
    assert res.status is RunStatus.OK, res.error
    assert {r.cve_id for r in res.records} == {"CVE-2026-131916"}
    assert CVE_103406 not in s.transport.urls()


def test_cvelist_cursor_older_than_log_is_unknown():
    s = cve_setup()
    res = run(s.connector, since=datetime(2026, 11, 1, tzinfo=UTC))
    _assert_unknown(res, "no llega al cursor")


def test_cvelist_link_outside_base_is_unknown():
    """El dato de la fuente no decide a qué host se conecta el monitor."""
    s = cve_setup()
    log = json.loads(fixture_bytes("cvelistv5", "deltaLog.json"))
    log[0]["new"][0]["githubLink"] = "https://ejemplo.invalid/CVE-2026-131916.json"
    s.transport.routes[s.main_url] = ok(json.dumps(log).encode())
    _assert_unknown(run(s.connector), "enlace fuera")
    assert not any("ejemplo.invalid" in u for u in s.transport.urls())


def test_cvelist_record_mismatch_is_unknown():
    s = cve_setup()
    s.transport.routes[CVE_131916] = ok(fixture_bytes("cvelistv5", "CVE-2026-103406.json"))
    _assert_unknown(run(s.connector), "no contiene")


def test_cvelist_rejected_record_is_withdrawn():
    """Registro sintético con el formato de un CVE rechazado."""
    rejected = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": "CVE-2026-131916",
            "state": "REJECTED",
            "assignerShortName": "jpcert",
            "datePublished": "2026-11-26T08:15:33.720Z",
            "dateRejected": "2026-11-26T08:18:00.000Z",
            "dateUpdated": "2026-11-26T08:18:00.000Z",
        },
        "containers": {"cna": {"rejectedReasons": [{"lang": "en", "value": "Duplicate."}]}},
    }
    s = cve_setup()
    s.transport.routes[CVE_131916] = ok(json.dumps(rejected).encode())
    res = run(s.connector)
    v = next(r for r in res.records if r.cve_id == "CVE-2026-131916")
    assert v.entity is Entity.VULNERABILITY
    assert v.value["withdrawn_at"] == datetime(2026, 11, 26, 8, 18, tzinfo=UTC)
    assert not [r for r in res.records if r.cve_id == "CVE-2026-131916" and r is not v]


def test_cvelist_too_many_records_is_unknown():
    _assert_unknown(run(cve_setup({"max_records": 1}).connector), "max_records")


# -- GHSA ------------------------------------------------------------------------------------------


def test_ghsa_follows_pages_and_normalizes():
    s = ghsa_setup()
    res = run(s.connector)
    assert s.transport.urls() == [GHSA_PAGE1, GHSA_PAGE2]
    assert [r.cve_id for r in res.records] == ["CVE-2026-69181", "CVE-2026-68539"]
    rec = res.records[0]
    assert rec.entity is Entity.AFFECTED_PRODUCT
    assert rec.value["ecosystem"] == "composer"
    assert rec.value["product"] == "tastyigniter/tastyigniter"
    assert rec.value["ranges"] == [
        {"type": "ghsa", "vulnerable_version_range": "< 4.3.1", "first_patched_version": "4.3.1"}
    ]
    assert rec.value["range_source"] == "ghsa:GHSA-rj59-9f77-mvg5"
    assert rec.url == "https://github.com/advisories/GHSA-rj59-9f77-mvg5"  # atribución CC-BY
    assert res.data_as_of == datetime(2026, 11, 25, 22, 54, 30, tzinfo=UTC)


def test_ghsa_stops_at_cursor():
    res = run(ghsa_setup().connector, since=datetime(2026, 11, 25, 20, 0, tzinfo=UTC))
    assert [r.cve_id for r in res.records] == ["CVE-2026-69181"]


def test_ghsa_pages_exhausted_before_cursor_is_unknown():
    s = ghsa_setup({"max_pages": 1})
    res = run(s.connector, since=datetime(2026, 11, 1, tzinfo=UTC))
    _assert_unknown(res, "sin llegar al cursor")


def test_ghsa_next_link_outside_api_is_unknown():
    s = ghsa_setup()
    s.transport.routes[GHSA_PAGE1] = ok(
        fixture_bytes("ghsa", "page1.json"),
        headers={"Link": '<https://ejemplo.invalid/advisories?page=2>; rel="next"'},
    )
    _assert_unknown(run(s.connector), "fuera de")


def test_ghsa_without_cve_is_skipped():
    s = ghsa_setup()
    page = json.loads(fixture_bytes("ghsa", "page2.json"))
    page[0]["cve_id"] = None
    s.transport.routes[GHSA_PAGE2] = ok(json.dumps(page).encode())
    res = run(s.connector)
    assert [r.cve_id for r in res.records] == ["CVE-2026-69181"]
    assert res.stats == {"sin_cve": 1}


def test_ghsa_token_comes_from_the_named_env_var(monkeypatch):
    monkeypatch.setenv("VS_TEST_GHSA_TOKEN", "token-de-prueba")
    s = ghsa_setup({"token_env": "VS_TEST_GHSA_TOKEN"})
    run(s.connector)
    assert s.transport.calls[0][1]["Authorization"] == "Bearer token-de-prueba"
    s2 = ghsa_setup()
    run(s2.connector)
    assert "Authorization" not in s2.transport.calls[0][1]


# -- OSV -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("osv_id", "eco", "expected"),
    [
        ("CGA-xxxx-xxxx-0001", "Wolfi", OsvPolicy.EXCLUDED),
        ("CGA-xxxx-xxxx-0001", "", OsvPolicy.EXCLUDED),
        ("GHSA-0000-0000-0001", "Chainguard", OsvPolicy.EXCLUDED),
        ("GHSA-0000-0000-0001", "Wolfi:2024", OsvPolicy.EXCLUDED),
        ("UBUNTU-CVE-2099-0001", "Ubuntu", OsvPolicy.SHARE_ALIKE),
        ("USN-0000-1", "Ubuntu", OsvPolicy.SHARE_ALIKE),
        ("ALPINE-CVE-2099-0001", "Alpine", OsvPolicy.SHARE_ALIKE),
        ("GHSA-0000-0000-0001", "npm", OsvPolicy.OPEN),
        ("RUSTSEC-2021-0003", "crates.io", OsvPolicy.OPEN),
        ("DEBIAN-CVE-2099-0002", "Debian", None),
        ("CVE-2099-0002", "", None),
    ],
)
def test_osv_policy(osv_id, eco, expected):
    assert policy_for(osv_id, eco) is expected


def test_osv_baseline_applies_the_license_policy():
    s = osv_setup()
    res = run(s.connector)
    assert res.status is RunStatus.OK, res.error
    urls = s.transport.urls()
    # Ni Chainguard/Wolfi ni fuentes sin licencia comprobada se llegan a pedir.
    assert not any("CGA-" in u or "DEBIAN-" in u for u in urls)
    # Fuera de la ventana de la carga inicial (24 h): no se pide.
    assert not any("RUSTSEC-2020-9999" in u for u in urls)

    by_cve = {r.cve_id: r for r in res.records}
    assert set(by_cve) == {"CVE-2099-0001", "CVE-2021-25900", "CVE-2099-0003"}
    assert by_cve["CVE-2099-0001"].share_alike is True  # Alpine, CC-BY-SA
    assert by_cve["CVE-2021-25900"].share_alike is False
    assert by_cve["CVE-2021-25900"].value["purl"] == "pkg:cargo/smallvec"
    assert by_cve["CVE-2021-25900"].value["range_source"] == "osv:RUSTSEC-2021-0003"
    # El affected de Wolfi del aviso sintético se descarta; queda solo el de npm.
    assert [r.value["ecosystem"] for r in res.records if r.cve_id == "CVE-2099-0003"] == ["npm"]
    assert res.stats == {
        "excluidos": 1,
        "sin_licencia_comprobada": 1,
        "affected_excluidos": 1,
    }


def test_osv_incremental_reads_only_after_cursor():
    s = osv_setup()
    res = run(s.connector, since=datetime(2026, 11, 26, 8, 5, tzinfo=UTC))
    assert {r.cve_id for r in res.records} == {"CVE-2099-0001"}


def test_osv_truncated_window_before_cursor_is_unknown():
    s = osv_setup(modified=ok(fixture_bytes("osv", "modified_id.csv"), status=206))
    res = run(s.connector, since=datetime(2026, 11, 1, tzinfo=UTC))
    _assert_unknown(res, "no llega al cursor")


def test_osv_asks_only_for_the_head_of_the_file():
    s = osv_setup({"head_bytes": 4096})
    run(s.connector)
    url, headers = s.transport.calls[0]
    assert url == osv.DEFAULT_MODIFIED_URL
    assert headers["Range"] == "bytes=0-4095"


def test_osv_record_with_wrong_id_is_unknown():
    s = osv_setup()
    s.transport.routes[OSV_BASE + "crates.io/RUSTSEC-2021-0003.json"] = ok(
        fixture_bytes("osv", "Alpine", "ALPINE-CVE-2099-0001.json")
    )
    _assert_unknown(run(s.connector), "no contiene")
