"""Feed OSV extendido: registro por CVE, índice con cursor, páginas por hora, 410, alertas,
derechos y esquema (PLAN.md §3, ADR-0007, ADR-0019, ADR-0022).

Todos los CVE, fabricantes, productos y paquetes son FICTICIOS (CVE-2099-*). Los hosts salen de
`config/brand.example.yaml` (ficticios), nunca del código.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from vs.feed.changes import ChangeEntry, CursorError, Gone, NotSealedError, decode_cursor
from vs.feed.config import FeedConfig, FeedConfigError, load_feed_config
from vs.feed.osv import alert_id, convert_ranges
from vs.feed.publish import FeedPublisher, classify
from vs.feed.rights import PUBLIC, Audience, engine_for_feed
from vs.feed.sign import LocalDevSigner, verify_detached
from vs.rules.engine import RulesConfig
from vs.rules.levels import Level
from vs.rules.lists import load_lists
from vs.sources.base import Entity, LicenseClass, Record

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "feed-1.0.0.json").read_text(encoding="utf-8"))
OSV_SCHEMA_PATH = ROOT / ".cache" / "osv-schema" / "schema-v1.9.2.json"
FIXTURES = ROOT / "tests" / "fixtures" / "lists"
LISTS = load_lists(
    FIXTURES / "exposed-products.rules.yaml", FIXTURES / "trusted-exploit-authors.rules.yaml"
)
CONFIG = load_feed_config(ROOT / "config" / "brand.example.yaml")
LICENSE = "example-commercial-license"
CLIENTS = Audience("client-1", frozenset(LicenseClass), frozenset({LICENSE}))

T0 = datetime(2099, 3, 1, 12, 0, tzinfo=UTC)  # carga inicial
T1 = T0 + timedelta(hours=1, minutes=5)
T2 = T1 + timedelta(hours=2)
T3 = T2 + timedelta(hours=1)
RCE_NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
SOURCES = ("cvelistv5", "cisa-kev", "epss", "exploits", "ghsa", "osv", "synthetic-restricted")

CVE_EXPOSED = "CVE-2099-1001"  # producto expuesto, RCE sin auth: C, luego B, luego A
CVE_OTHER = "CVE-2099-1002"  # paquete npm fuera de las listas: siempre `none`
CVE_RESTRICTED = "CVE-2099-1003"  # su único A sale de una fuente `restricted`


def validator(name: str | None = None) -> Draft202012Validator:
    schema = SCHEMA if name is None else {"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]}
    return Draft202012Validator(schema, format_checker=FormatChecker())


def assert_valid(doc, name: str | None = None) -> None:
    errors = sorted(validator(name).iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)


# -- registros sintéticos (como los deja el ejecutor) -----------------------------------------


def vuln(cve, *, published=T1, observed=T1, withdrawn=None, product="Exampled") -> Record:
    return Record(
        source="cvelistv5",
        cve_id=cve,
        kind="vulnerability",
        license_class=LicenseClass.OPEN,
        entity=Entity.VULNERABILITY,
        value={
            "cna": "example-cna",
            "cvss_vector": RCE_NET,
            "cvss_source": "cna",
            "cwe": ["CWE-787"],
            "vendor": "Examplesoft",
            "product": product,
            "withdrawn_at": withdrawn,
        },
        source_published_at=published - timedelta(hours=1),
        observed_at=observed,
        url=f"https://www.cve.org/CVERecord?id={cve}",
    )


def cve5_affected(cve, observed=T1) -> Record:
    return Record(
        source="cvelistv5",
        cve_id=cve,
        kind="affected_product",
        license_class=LicenseClass.OPEN,
        entity=Entity.AFFECTED_PRODUCT,
        value={
            "vendor": "Examplesoft",
            "product": "Exampled",
            "cpe": "cpe:2.3:a:examplesoft:exampled:*:*:*:*:*:*:*:*",
            "purl": None,
            "ecosystem": None,
            "ranges": [
                {
                    "type": "cve5",
                    "default_status": "unaffected",
                    "versions": [
                        {
                            "version": "1.0.0",
                            "lessThan": "1.4.2",
                            "status": "affected",
                            "versionType": "semver",
                        },
                        {
                            "version": "1.5.0",
                            "lessThan": "1.5.3",
                            "status": "affected",
                            "versionType": "semver",
                        },
                    ],
                }
            ],
            "range_source": "cna:example-cna",
        },
        source_published_at=observed,
        observed_at=observed,
        url=f"https://www.cve.org/CVERecord?id={cve}",
    )


def ghsa_affected(cve, observed=T1, ghsa="GHSA-xxxx-yyyy-zzzz") -> Record:
    return Record(
        source="ghsa",
        cve_id=cve,
        kind="affected_product",
        license_class=LicenseClass.OPEN,
        entity=Entity.AFFECTED_PRODUCT,
        value={
            "vendor": None,
            "product": "example-left-pad",
            "cpe": None,
            "purl": None,
            "ecosystem": "npm",
            "ranges": [
                {
                    "type": "ghsa",
                    "vulnerable_version_range": ">= 2.0.0, < 2.3.1",
                    "first_patched_version": "2.3.1",
                }
            ],
            "range_source": f"ghsa:{ghsa}",
        },
        source_published_at=observed,
        observed_at=observed,
        url=f"https://github.com/advisories/{ghsa}",
    )


def osv_affected(cve, observed=T1, share_alike=False) -> Record:
    return Record(
        source="osv",
        cve_id=cve,
        kind="affected_product",
        license_class=LicenseClass.OPEN,
        entity=Entity.AFFECTED_PRODUCT,
        value={
            "vendor": None,
            "product": "example-sa-package" if share_alike else "example-pypi-pkg",
            "cpe": None,
            "purl": "pkg:pypi/example-pypi-pkg",
            "ecosystem": "Ubuntu:24.04:LTS" if share_alike else "PyPI",
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1"}]}],
            "range_source": "osv:UBUNTU-CVE-2099-1002" if share_alike else "osv:PYSEC-2099-1",
        },
        source_published_at=observed,
        observed_at=observed,
        url="https://osv.dev/vulnerability/PYSEC-2099-1",
        share_alike=share_alike,
    )


def sig(cve, kind, value, *, source, observed, restricted=False, url=None) -> Record:
    return Record(
        source=source,
        cve_id=cve,
        kind=kind,
        license_class=LicenseClass.RESTRICTED if restricted else LicenseClass.OPEN,
        licensee=LICENSE if restricted else None,
        value=value,
        observed_at=observed,
        url=url,
    )


def ssvc(cve, observed=T1):
    value = {"exploitation": "none", "automatable": "yes", "technical_impact": "total"}
    return sig(cve, "ssvc", value, source="cvelistv5", observed=observed)


def msf(cve, observed):
    value = {"origin": "metasploit", "path": "exploit/linux/http/exampled_rce"}
    url = "https://github.com/rapid7/metasploit-framework/blob/master/modules/x.rb"
    return sig(cve, "exploit", value, source="exploits", observed=observed, url=url)


def kev(cve, observed):
    url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=" + cve
    value = {"date_added": "2099-03-01"}
    return sig(cve, "kev_cisa", value, source="cisa-kev", observed=observed, url=url)


def epss(cve, day, score, observed):
    value = {"epss": score, "percentile": 0.5, "model_version": "v4", "score_date": day}
    return sig(cve, "epss", value, source="epss", observed=observed)


def vulncheck(cve, observed):
    value = {"marker": "RESTRICTED-PAYLOAD-DO-NOT-PUBLISH"}
    url = "https://restricted.example.invalid/x"
    return sig(cve, "kev_vulncheck", value, source="synthetic-restricted", observed=observed,
               restricted=True, url=url)  # fmt: skip


# -- montaje ----------------------------------------------------------------------------------


def make(audience=PUBLIC, **kw):
    engine = engine_for_feed(audience, LISTS, RulesConfig(recent_days=14))
    for s in SOURCES:
        engine.complete_baseline(s, T0)
    signer = LocalDevSigner.generate(CONFIG.key_id)
    return engine, FeedPublisher(audience, CONFIG, signer, LISTS, **kw)


def run_day(audience=PUBLIC, **kw):
    """C a T1, B a T2 (exploit), A a T3 (KEV); más una CVE `none` y una con A restringido."""
    engine, pub = make(audience, **kw)
    batch1 = [
        vuln(CVE_EXPOSED),
        cve5_affected(CVE_EXPOSED),
        ssvc(CVE_EXPOSED),
        vuln(CVE_OTHER, product="example-left-pad"),
        ghsa_affected(CVE_OTHER),
        osv_affected(CVE_OTHER),
        osv_affected(CVE_OTHER, share_alike=True),
        vuln(CVE_RESTRICTED, product="Unlisted"),
        vulncheck(CVE_RESTRICTED, T1),
    ]
    engine.ingest(batch1, T1)
    pub.publish_from_engine(engine, T1)
    engine.ingest([msf(CVE_EXPOSED, T2)], T2)
    pub.publish_from_engine(engine, T2)
    engine.ingest([kev(CVE_EXPOSED, T3)], T3)
    pub.publish_from_engine(engine, T3)
    return engine, pub


# -- IDs y configuración ------------------------------------------------------------------------


def test_alert_id_is_stable_and_strict():
    assert alert_id("CVE-2099-1001") == "VS-CVE-2099-1001"
    assert alert_id("CVE-2099-1001") == alert_id("CVE-2099-1001")
    for bad in ("cve-2099-1001", "GHSA-xxxx-yyyy-zzzz", "CVE-2099-1", "VS-CVE-2099-1001"):
        with pytest.raises(ValueError):
            alert_id(bad)


def test_id_does_not_change_across_updates():
    _, pub = run_day()
    ids = {e.id for e in pub.logs["all"].entries() if e.id.endswith("1001")}
    assert ids == {"VS-CVE-2099-1001"}


def test_hosts_come_from_config():
    _, pub = run_day()
    now = T3 + timedelta(days=40)
    with pytest.raises(Gone) as exc:
        pub.changes_head("all", pub.logs["all"].entries()[0].cursor, now)
    assert exc.value.snapshot_url.startswith(CONFIG.api_base + "/v1/feed/all/snapshot/")
    # Ningún host escrito a mano en el código del feed (ADR-0016).
    for path in (ROOT / "src" / "vs" / "feed").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "example.org" not in text and "https://api." not in text, path


def test_feed_config_rejects_bad_values():
    with pytest.raises(FeedConfigError):
        load_feed_config(ROOT / "config" / "brand.example.yaml", page_limit=0)
    with pytest.raises(FeedConfigError):
        FeedConfig(api_base="http://insecure.example.invalid", key_id="k")


def test_signer_kid_must_match_config():
    with pytest.raises(ValueError):
        FeedPublisher(PUBLIC, CONFIG, LocalDevSigner.generate("other-kid"))


# -- registro OSV ---------------------------------------------------------------------------------


def test_records_validate_own_schema():
    _, pub = run_day()
    for ident in ("VS-CVE-2099-1001", "VS-CVE-2099-1002", "VS-CVE-2099-1003"):
        assert_valid(pub.record(ident))
        assert_valid(json.loads(pub.vuln(ident).body))


def test_records_validate_osv_schema_except_id_prefix():
    """OSV 1.9.2 solo admite prefijos registrados en `id`; «VS-» no lo está (pregunta abierta).
    Todo lo demás del registro tiene que validar contra el esquema oficial."""
    if not OSV_SCHEMA_PATH.exists():
        pytest.skip(
            "esquema OSV no descargado: https://raw.githubusercontent.com/ossf/osv-schema/"
            "v1.9.2/validation/schema.json → .cache/osv-schema/schema-v1.9.2.json"
        )
    osv = Draft202012Validator(json.loads(OSV_SCHEMA_PATH.read_text(encoding="utf-8")))
    _, pub = run_day()
    for ident in ("VS-CVE-2099-1001", "VS-CVE-2099-1002", "VS-CVE-2099-1003"):
        errors = list(osv.iter_errors(pub.record(ident)))
        assert [list(e.path) for e in errors] == [["id"]], [e.message for e in errors]
        # Con un prefijo registrado (p. ej. `CVE-`), valida entero.
        doc = {**pub.record(ident), "id": ident.removeprefix("VS-")}
        assert not list(osv.iter_errors(doc))


def test_record_content():
    _, pub = run_day()
    rec = pub.record("VS-CVE-2099-1001")
    ext = rec["database_specific"]["vuln_sentinel"]
    assert rec["schema_version"] == "1.9.2"
    assert rec["aliases"][0] == CVE_EXPOSED
    assert rec["severity"] == [{"type": "CVSS_V3", "score": RCE_NET, "source": "CNA"}]
    assert ext["level"] == "A"
    assert ext["impact_class"] == "rce"
    assert ext["level_reason"] == ["A.kev_cisa"]
    assert [h["level"] for h in ext["level_history"]] == ["C", "B", "A"]
    assert [c["type"] for c in ext["changes"]] == ["new", "level_up", "poc_added", "level_up",
                                                   "kev_added"]  # fmt: skip
    assert ext["signals"]["kev"]["cisa"] is True
    assert ext["signals"]["exploits"][0]["rule"] == "E1"
    assert ext["signals"]["fix"] == {"available": True, "versions": ["1.4.2", "1.5.3"]}
    # Producto sin ecosistema OSV: sin `package`, con CPE y rangos.
    (aff,) = rec["affected"]
    assert "package" not in aff
    assert aff["ranges"] == [
        {
            "type": "SEMVER",
            "events": [
                {"introduced": "1.0.0"},
                {"fixed": "1.4.2"},
                {"introduced": "1.5.0"},
                {"fixed": "1.5.3"},
            ],
        }
    ]
    assert aff["database_specific"]["cpe"] == ["cpe:2.3:a:examplesoft:exampled:*:*:*:*:*:*:*:*"]
    # Dos marcas de tiempo en las fuentes.
    for s in ext["sources"]:
        assert s["observed_at"]
    assert rec["published"] < rec["modified"]


def test_package_ecosystems_and_aliases():
    _, pub = run_day()
    rec = pub.record("VS-CVE-2099-1002")
    pkgs = sorted((a["package"]["ecosystem"], a["package"]["name"]) for a in rec["affected"])
    assert pkgs == [("PyPI", "example-pypi-pkg"), ("npm", "example-left-pad")]
    npm = next(a for a in rec["affected"] if a["package"]["ecosystem"] == "npm")
    assert npm["ranges"] == [
        {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.3.1"}]}
    ]
    assert rec["aliases"] == [CVE_OTHER, "GHSA-xxxx-yyyy-zzzz", "PYSEC-2099-1"]
    assert rec["database_specific"]["vuln_sentinel"]["level"] == "none"


def test_share_alike_is_excluded_by_default():
    _, pub = run_day()
    body = pub.vuln("VS-CVE-2099-1002").body
    assert b"example-sa-package" not in body and b"UBUNTU-CVE" not in body
    assert pub.stats.dropped_share_alike > 0


@pytest.mark.parametrize(
    ("ranges", "events", "versions", "raw"),
    [
        # CVE 5: lessThanOrEqual → last_affected (en un rango aparte de los `fixed`)
        (
            [{"type": "cve5", "versions": [
                {"version": "2.0", "lessThanOrEqual": "2.4", "status": "affected"},
                {"version": "3.0", "lessThan": "3.2", "status": "affected"},
            ]}],
            [
                {"type": "ECOSYSTEM", "events": [{"introduced": "3.0"}, {"fixed": "3.2"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"last_affected": "2.4"}]},
            ],
            [],
            0,
        ),
        # CVE 5: versión suelta y una «unaffected» (no exacta: se guarda el original)
        (
            [{"type": "cve5", "versions": [
                {"version": "4.1", "status": "affected"},
                {"version": "4.2", "status": "unaffected"},
            ]}],
            [],
            ["4.1"],
            1,
        ),
        # GHSA: «>» no es expresable → original
        ([{"type": "ghsa", "vulnerable_version_range": "> 1.0, < 2.0"}], [], [], 1),
        # GHSA: «<= x» sin cota inferior → introduced 0 + last_affected
        (
            [{"type": "ghsa", "vulnerable_version_range": "<= 0.9.1"}],
            [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "0.9.1"}]}],
            [],
            0,
        ),
        # GHSA: «= x» → versión suelta
        ([{"type": "ghsa", "vulnerable_version_range": "= 1.2.3"}], [], ["1.2.3"], 0),
        # OSV: pasa tal cual; `versions` de OSV
        (
            [
                {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]},
                {"type": "versions", "versions": ["0.9"]},
            ],
            [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
            ["0.9"],
            0,
        ),
        # Desconocido → original
        ([{"type": "weird", "x": 1}], [], [], 1),
    ],
)  # fmt: skip
def test_convert_ranges(ranges, events, versions, raw):
    got, vers, raw_out = convert_ranges(ranges)
    assert got == events
    assert vers == versions
    assert len(raw_out) == raw


def test_withdrawn_record():
    engine, pub = make()
    engine.ingest([vuln(CVE_OTHER), ghsa_affected(CVE_OTHER)], T1)
    pub.publish_from_engine(engine, T1)
    engine.ingest([vuln(CVE_OTHER, observed=T2, withdrawn=T2)], T2)
    (entry,) = pub.publish_from_engine(engine, T2)
    assert entry.type == "withdrawn"
    rec = pub.record(entry.id)
    assert rec["withdrawn"] == "2099-03-01T15:05:00Z"
    assert_valid(rec)


def test_epss_delta_and_jump_threshold():
    engine, pub = make(epss_jump=0.2)
    engine.ingest([vuln(CVE_OTHER), epss(CVE_OTHER, "2099-02-20", 0.01, T1)], T1)
    pub.publish_from_engine(engine, T1)
    engine.ingest([epss(CVE_OTHER, "2099-03-01", 0.40, T2)], T2)
    (entry,) = pub.publish_from_engine(engine, T2)
    sig_epss = pub.record(entry.id)["database_specific"]["vuln_sentinel"]["signals"]["epss"]
    assert sig_epss["delta_7d"] == pytest.approx(0.39)
    assert entry.type == "epss_jump"
    # Sin umbral (por defecto) no se emite `epss_jump`.
    engine2, pub2 = make()
    engine2.ingest([vuln(CVE_OTHER), epss(CVE_OTHER, "2099-02-20", 0.01, T1)], T1)
    pub2.publish_from_engine(engine2, T1)
    engine2.ingest([epss(CVE_OTHER, "2099-03-01", 0.40, T2)], T2)
    (entry2,) = pub2.publish_from_engine(engine2, T2)
    assert entry2.type == "updated"


def test_classify_priority():
    _, pub = run_day()
    rec = pub.record("VS-CVE-2099-1001")
    assert classify(None, rec) == ["new"]
    assert classify(rec, rec) == ["updated"]


# -- derechos (ADR-0022) --------------------------------------------------------------------------


def test_public_feed_never_contains_restricted_data():
    _, pub = run_day()
    rec = pub.record("VS-CVE-2099-1003")
    body = pub.vuln("VS-CVE-2099-1003").body
    assert b"RESTRICTED-PAYLOAD" not in body and b"restricted.example.invalid" not in body
    assert b"synthetic-restricted" not in body
    # Sin fuente abierta que lo diga, el A restringido no existe en el feed público.
    assert rec["database_specific"]["vuln_sentinel"]["level"] == "none"
    assert pub.stats.dropped_by_rights == 0  # el motor ya lo había descartado
    for doc in (pub.alerts_latest(T3), pub.changes_head("all", None, T3)):
        assert b"RESTRICTED-PAYLOAD" not in doc.body


def test_publisher_filters_even_without_engine():
    _, pub = make()
    entry = pub.publish(
        CVE_RESTRICTED, [vuln(CVE_RESTRICTED), vulncheck(CVE_RESTRICTED, T1)], Level.NONE, [], T1
    )
    assert entry is not None
    assert b"RESTRICTED-PAYLOAD" not in pub.vuln(entry.id).body
    assert pub.stats.dropped_by_rights == 1
    # Solo restringido: no hay nada que publicar.
    assert (
        pub.publish("CVE-2099-1004", [vulncheck("CVE-2099-1004", T1)], Level.NONE, [], T1) is None
    )


def test_clients_feed_with_license_sees_restricted_level():
    _, pub = run_day(CLIENTS)
    rec = pub.record("VS-CVE-2099-1003")
    assert rec["database_specific"]["vuln_sentinel"]["level"] == "A"
    assert_valid(rec)


def test_history_from_other_feed_is_rejected():
    engine_c, _ = run_day(CLIENTS)
    _, pub = make()
    with pytest.raises(ValueError):
        pub.publish(CVE_EXPOSED, engine_c.records(CVE_EXPOSED), Level.A, engine_c.history, T3)
    with pytest.raises(ValueError):
        pub.publish_from_engine(engine_c, T3)


# -- índice de cambios ----------------------------------------------------------------------------


def test_all_and_alerts_feeds():
    _, pub = run_day()
    all_ids = [e.id for e in pub.logs["all"].entries()]
    alert_entries = pub.logs["alerts"].entries()
    assert set(all_ids) == {"VS-CVE-2099-1001", "VS-CVE-2099-1002", "VS-CVE-2099-1003"}
    assert {e.id for e in alert_entries} == {"VS-CVE-2099-1001"}
    assert [e.level for e in alert_entries] == [Level.C, Level.B, Level.A]
    latest = json.loads(pub.alerts_latest(T3).body)
    assert latest["alerts"] == [
        {
            "id": "VS-CVE-2099-1001",
            "modified": pub.record("VS-CVE-2099-1001")["modified"],
            "level": "A",
            "sha256": pub.vuln("VS-CVE-2099-1001").sha256,
        }
    ]
    assert_valid(latest, "alerts_latest")


def test_unchanged_republish_gives_no_entry():
    engine, pub = run_day()
    before, unchanged = len(pub.logs["all"]), pub.stats.unchanged
    assert pub.publish_from_engine(engine, T3 + timedelta(minutes=10)) == []
    assert len(pub.logs["all"]) == before
    assert pub.stats.unchanged - unchanged == 3


def test_entry_hash_matches_record_bytes_and_etag():
    _, pub = run_day()
    latest = {}
    for entry in pub.logs["all"].entries():
        latest[entry.id] = entry  # la última entrada de cada id es la versión vigente
    for ident, entry in latest.items():
        doc = pub.vuln(ident)
        assert entry.sha256 == doc.sha256
        assert json.loads(doc.body)["modified"] == entry.to_json()["modified"]
        assert doc.headers["ETag"] == f'"{doc.sha256}"'
        assert doc.headers["X-VS-Schema"] == "1.0.0"


def test_cursor_paging_is_stable_and_complete():
    engine, pub = make()
    cves = [f"CVE-2099-{2000 + i}" for i in range(25)]
    for i, cve in enumerate(cves):
        engine.ingest([vuln(cve, observed=T1)], T1)
        pub.publish_from_engine(engine, T1 + timedelta(seconds=i // 5), [cve])
    seen, cursor, pages = [], None, 0
    while True:
        doc = json.loads(pub.changes_head("all", cursor, T2, limit=7).body)
        assert_valid(doc, "changes_page")
        seen += [e["id"] for e in doc["entries"]]
        cursor, pages = doc["next"], pages + 1
        if not doc["has_more"]:
            break
    assert pages == 4
    assert seen == [alert_id(c) for c in cves]  # orden (modified, id), sin huecos ni repetidos
    # Al final, el cursor no trae nada y se mantiene.
    tail = json.loads(pub.changes_head("all", cursor, T2).body)
    assert tail["entries"] == [] and tail["next"] == cursor
    assert decode_cursor(cursor)[1] == alert_id(cves[-1])


def test_same_second_updates_get_strictly_increasing_modified():
    engine, pub = make()
    engine.ingest([vuln(CVE_OTHER)], T1)
    pub.publish_from_engine(engine, T1)
    engine.ingest([ghsa_affected(CVE_OTHER, observed=T1)], T1)
    pub.publish_from_engine(engine, T1)
    a, b = pub.logs["all"].entries()
    assert b.modified > a.modified
    page = json.loads(pub.changes_head("all", a.cursor, T2).body)
    assert [e["id"] for e in page["entries"]] == [b.id]
    # Llegan rangos con versión corregida: dos tipos; el índice lleva el de más prioridad.
    assert b.type == "fix_released"
    changes = pub.record(b.id)["database_specific"]["vuln_sentinel"]["changes"]
    assert [c["type"] for c in changes] == ["new", "fix_released", "range_completed"]


def test_page_limits():
    _, pub = run_day()
    doc = json.loads(pub.changes_head("all", None, T3, limit=10_000).body)
    assert len(doc["entries"]) == len(pub.logs["all"])
    assert pub.logs["all"].page(None, 10_000, 5000, T3)[0]  # se recorta a 5.000, no falla
    with pytest.raises(CursorError):
        pub.changes_head("all", None, T3, limit=0)
    for bad in ("nope", "2099-03-01T12:00:00Z,CVE-2099-1", "2099-03-01T12:00:00,VS-CVE-2099-1001"):
        with pytest.raises(CursorError):
            pub.changes_head("all", bad, T3)


def test_head_ttl_and_sealed_pages_immutable():
    _, pub = run_day()
    head = pub.changes_head("all", None, T3)
    assert head.headers["Cache-Control"] == "public, max-age=60"
    now = T3 + timedelta(hours=2)
    pages = pub.sealed_pages("all", now)
    hours = [json.loads(p.body)["hour"] for p in pages]
    assert hours == ["2099-03-01T13", "2099-03-01T15", "2099-03-01T16"]
    for p in pages:
        assert p.headers["Cache-Control"] == "public, max-age=31536000, immutable"
        assert p.path.startswith("/v1/feed/all/changes/") and p.path.endswith(".json")
        assert_valid(json.loads(p.body), "changes_page")
    # Una página sellada da los mismos bytes en cualquier momento posterior.
    later = pub.sealed_page("all", "2099-03-01T13", now + timedelta(days=3))
    assert later.body == pages[0].body
    # La hora en curso no está sellada.
    with pytest.raises(NotSealedError):
        pub.sealed_page("all", now.strftime("%Y-%m-%dT%H"), now)
    # Y en el índice no se puede añadir nada a una hora cerrada.
    first = pub.logs["all"].entries()[0]
    late = ChangeEntry(first.id, first.modified, Level.NONE, "updated", first.sha256)
    with pytest.raises(ValueError):
        pub.logs["all"].append(late)


def test_gone_beyond_retention():
    _, pub = run_day()
    cursor = pub.logs["all"].entries()[0].cursor
    now = T1 + timedelta(days=31)
    with pytest.raises(Gone) as exc:
        pub.changes_head("all", cursor, now)
    doc = pub.gone_document("/v1/feed/all/changes", exc.value)
    assert doc.status == 410
    body = json.loads(doc.body)
    assert body["snapshot"] == CONFIG.url("/v1/feed/all/snapshot/2099-03-31.zip")
    assert_valid(body, "gone")
    with pytest.raises(Gone):
        pub.sealed_page("all", "2099-03-01T13", now)
    with pytest.raises(Gone):
        pub.changes_head("alerts", pub.logs["alerts"].entries()[0].cursor, now)
    # Dentro de la retención sigue sirviéndose.
    assert pub.changes_head("all", cursor, T1 + timedelta(days=29)).status == 200
    # Sin cursor se empieza en el horizonte; la poda quita lo antiguo.
    assert json.loads(pub.changes_head("all", None, now).body)["entries"] == []
    total = len(pub.logs["all"]) + len(pub.logs["alerts"])
    assert pub.prune(now) == total
    assert len(pub.logs["all"]) == 0 and len(pub.logs["alerts"]) == 0


# -- firma de los documentos --------------------------------------------------------------------


def test_every_document_is_signed_over_exact_bytes():
    _, pub = run_day()
    keys = json.loads(pub.keys().body)
    assert_valid(keys, "jwks")
    now = T3 + timedelta(hours=2)
    docs = [
        pub.vuln("VS-CVE-2099-1001"),
        pub.changes_head("all", None, now),
        pub.changes_head("alerts", None, now),
        pub.alerts_latest(now),
        *pub.sealed_pages("all", now),
    ]
    for doc in docs:
        jws = pub.signature(doc)
        assert jws.path == doc.path + ".jws"
        assert jws.headers["Content-Type"] == "application/jose"
        assert verify_detached(jws.body.decode(), doc.body, keys) == CONFIG.key_id
        if "Cache-Control" in doc.headers:
            assert jws.headers["Cache-Control"] == doc.headers["Cache-Control"]
