"""Generadores de listas (F1a-0, R7): deterministas, con esquema y sin nombres fuera de la regla."""

import datetime as dt
import json
import random
from pathlib import Path

import pytest
import yaml

from vs.lists import build_exposed_products as bep
from vs.lists import build_trusted_authors as bta
from vs.lists import cvelist, deployment
from vs.lists.common import months_before
from vs.lists.schema import EMAIL_RE, validate_authors, validate_exposed

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "lists"
CUTOFF = dt.date(2026, 11, 26)
KEV = (FIX / "kev_small.json").read_bytes()
MSF = (FIX / "msf_small.json").read_bytes()
SURVEY = (FIX / "survey_small.json").read_bytes()
RECORDS = {
    cve: json.dumps(rec, sort_keys=True).encode()
    for cve, rec in json.loads((FIX / "cvelist_small.json").read_bytes()).items()
    if cve.startswith("CVE-")
}


def _ids(items):
    return [i["id"] for i in items]


def _build(kev=KEV, records=RECORDS, survey=None):
    return bep.build(kev, CUTOFF, records, survey)


def _product(doc, pid):
    return next(p for p in doc["products"] if p["id"] == pid)


# --- determinismo -------------------------------------------------------------------------------


def test_exposed_is_deterministic():
    assert bep.render(_build()) == bep.render(_build())


def test_exposed_ignores_input_order():
    data = json.loads(KEV)
    random.Random(7).shuffle(data["vulnerabilities"])  # noqa: S311 (orden de prueba, no cripto)
    shuffled = json.dumps(data).encode()
    a, b = _build(), _build(kev=shuffled)
    for key in ("products", "needs_review", "below_threshold", "out_of_scope", "stats"):
        assert a[key] == b[key]
    assert a["canonicalization"] == b["canonicalization"]
    assert a["inputs"][0]["sha256"] != b["inputs"][0]["sha256"]


def test_authors_is_deterministic():
    assert bta.render(bta.build(MSF, CUTOFF)) == bta.render(bta.build(MSF, CUTOFF))


def test_authors_ignore_input_order():
    data = json.loads(MSF)
    shuffled = json.dumps(dict(reversed(list(data.items())))).encode()
    a, b = bta.build(MSF, CUTOFF), bta.build(shuffled, CUTOFF)
    assert a["authors"] == b["authors"]
    assert a["needs_review"] == b["needs_review"]


def test_months_before():
    assert months_before(dt.date(2026, 11, 26), 36) == dt.date(2023, 11, 26)
    assert months_before(dt.date(2026, 3, 31), 1) == dt.date(2026, 2, 28)


# --- resultado esperado con los fixtures --------------------------------------------------------


def test_exposed_expected_sections():
    doc = _build()
    assert _ids(doc["products"]) == [
        "acme--edge-firewall",
        "acme--secure-access",
        "acme--vpn-gateway",
        "vandelay--gateway-thing",
    ]
    assert _ids(doc["below_threshold"]) == ["globex--mail-relay", "umbrella--email-firewall"]
    assert _ids(doc["needs_review"]) == ["initech--multiple-products"]
    assert doc["needs_review"][0]["reason"] == "producto genérico en KEV"
    assert doc["out_of_scope"] == ["hooli--desktop-os", "initech--office-suite", "soylent--widget"]
    vpn = _product(doc, "acme--vpn-gateway")
    assert vpn["vendor"] == "Acme" and vpn["product"] == "VPN Gateway"
    # fuera de ventana (2020) y posterior al corte (2026-12-01) no cuentan
    assert vpn["evidence"]["cves"] == [
        "CVE-2024-90003",
        "CVE-2025-90002",
        "CVE-2026-90001",
        "CVE-2026-90018",
    ]
    # vpn de Acme: 4 de VPN Gateway + 2 de Secure Access (una reasignada desde Globex, R1)
    assert vpn["evidence"]["vendor_category_entries"] == 6
    assert {"vendor": "ACME", "product": "VPN gateway"} in vpn["aliases"]
    umbrella = doc["below_threshold"][1]
    assert umbrella["category"] == "firewall"  # firewall y mail por nombre: gana `precedence`


def test_category_from_descriptions():
    thing = _product(_build(), "vandelay--gateway-thing")
    assert thing["category"] == "web-proxy"
    assert thing["category_source"] == "descriptions"
    assert thing["matched"] == ["descriptions:web-proxy:2/3"]


# --- canonicalización ---------------------------------------------------------------------------


def test_canonicalization_merges_variants_into_one_product():
    doc = _build()
    efw = _product(doc, "acme--edge-firewall")
    assert {(a["vendor"], a["product"]) for a in efw["aliases"]} == {
        ("Acme", "Edge Firewall (EFW) and VPN Gateway"),
        ("Acme", "EFW Software"),
        ("Acme", "Secure Edge Firewall"),
        ("Acme", "Edge Firewall"),
    }
    assert efw["abbreviations"] == ["EFW"]
    assert efw["evidence"]["cves"] == [
        "CVE-2026-90018",
        "CVE-2026-90019",
        "CVE-2026-90020",
        "CVE-2026-90027",
    ]
    merges = {m["id"]: m for m in doc["canonicalization"]["merges"]}
    assert merges["acme--edge-firewall"]["merged"] == [
        "edge-firewall",
        "efw",
        "secure-edge-firewall",
    ]
    # ningún id aparece dos veces entre las secciones
    all_ids = [
        *_ids(doc["products"]),
        *_ids(doc["needs_review"]),
        *_ids(doc["below_threshold"]),
        *doc["out_of_scope"],
    ]
    assert len(all_ids) == len(set(all_ids))


def test_canonicalization_vendor_reassignment_and_generic_resolution():
    doc = _build()
    log = doc["canonicalization"]
    assert [r["cve"] for r in log["vendor_reassignments"]] == ["CVE-2026-90021"]
    assert log["vendor_reassignments"][0]["to_vendor"] == "Acme"
    access = _product(doc, "acme--secure-access")
    assert {"vendor": "Globex", "product": "Acme Secure Access"} in access["aliases"]
    assert [r["to"] for r in log["resolved_generic"]] == ["hooli--desktop-os"]


@pytest.mark.parametrize(
    ("product", "expected"),
    [
        ("Edge Firewall (EFW) and VPN Gateway", ["Edge Firewall (EFW)", "VPN Gateway"]),
        ("NetScaler ADC and Gateway", ["NetScaler ADC", "NetScaler Gateway"]),
        (
            "Catalyst SD-WAN Controller and Manager",
            ["Catalyst SD-WAN Controller", "Catalyst SD-WAN Manager"],
        ),
        ("ESXi, Workstation, and Fusion", ["ESXi", "Workstation", "Fusion"]),
        ("Jira Server and Data Center", ["Jira Server"]),
        ("Acrobat and Reader", ["Acrobat", "Reader"]),
    ],
)
def test_split_product(product, expected):
    assert bep.split_product(product) == expected


@pytest.mark.parametrize(
    ("name", "vendor", "expected"),
    [
        ("WordPress Core", "WordPress", "Core"),
        ("Community Edition", "GitLab", "GitLab"),
        ("GitLab CE/EE", "GitLab", "GitLab"),
        ("MongoDB Server", "MongoDB", "MongoDB Server"),
        ("Wing FTP Server", "Wing FTP Server", "Wing FTP Server"),
    ],
)
def test_strip_vendor(name, vendor, expected):
    assert bep.strip_vendor(name, [vendor], vendor) == expected


# --- CPE ----------------------------------------------------------------------------------------


def test_cpe_from_cvelist_by_tokens():
    doc = _build()
    assert _product(doc, "acme--vpn-gateway")["cpe"] == ["cpe:2.3:o:acme:vpn_gateway"]
    efw = _product(doc, "acme--edge-firewall")
    assert efw["cpe"] == ["cpe:2.3:o:acme:edge_firewall"]
    assert efw["cpe_rule"] == "tokens"
    assert {"vendor": "Acme", "product": "VPN Gateway"} not in efw["cna"]


def test_no_product_without_cpe_or_reason():
    for doc in (_build(), _build(records=None)):
        for p in doc["products"]:
            assert p["cpe"] or p["cpe_missing_reason"], p["id"]
    doc = _build()
    assert _product(doc, "acme--secure-access")["cpe_missing_reason"] == (
        "sin registros cvelistV5 para sus CVE"
    )
    thing = _product(doc, "vandelay--gateway-thing")
    assert thing["cpe"] == [] and "no traen CPE" in thing["cpe_missing_reason"]
    assert thing["cna"] == [{"vendor": "Vandelay Industries", "product": "Gateway Thing"}]


def test_cvelist_parse_and_hash():
    parsed = cvelist.parse(RECORDS["CVE-2026-90020"])
    assert parsed == {"cna": [("Acme", "Secure Edge Firewall")], "cpe": []}
    assert cvelist.record_url("CVE-2026-90020").endswith("/cves/2026/90xxx/CVE-2026-90020.json")
    a = cvelist.records_hash(RECORDS)
    b = cvelist.records_hash(dict(reversed(list(RECORDS.items()))))
    assert a == b and a.startswith("sha256:")


# --- pata de despliegue -------------------------------------------------------------------------


def test_deployment_leg_is_deterministic_with_fixture():
    a, b = deployment.build(SURVEY), deployment.build(SURVEY)
    assert a == b
    assert a["status"] == "active" and a["n"] == deployment.N == 5
    assert [p["name"] for p in a["products"]] == [
        "Alpha Server",
        "Bravo HTTPd",
        "Charlie Web",
        "Delta Server",  # empate a 4.0 con Epsilon Proxy: decide el nombre
        "Epsilon Proxy",
    ]
    assert [p["rank"] for p in a["products"]] == [1, 2, 3, 4, 5]
    assert all(p["category"] == "web-proxy" for p in a["products"])
    assert "share" not in a["products"][0]  # solo nombres, puesto, fuente y fecha
    data = json.loads(SURVEY)
    data["ranking"].reverse()
    c = deployment.build(json.dumps(data).encode())
    assert c["products"] == a["products"]


def test_deployment_leg_pending_without_source():
    leg = deployment.build(None)
    assert leg["status"] == "pending" and leg["products"] == [] and leg["options_found"]
    doc = yaml.safe_load(bep.render(_build(survey=SURVEY)))
    assert validate_exposed(doc) == []


# --- autores ------------------------------------------------------------------------------------


def test_authors_expected_sections():
    doc = bta.build(MSF, CUTOFF)
    names = [a["name"] for a in doc["authors"]]
    assert names == ["Alice Example", "bob", "Carol", "Dan (dan-handle)"]
    alice = doc["authors"][0]
    assert alice["modules"] == [
        "exploit/linux/http/acme_vpn_rce",
        "exploit/multi/http/globex_mail_rce",
    ]
    reasons = sorted(r["reason"] for r in doc["needs_review"])
    assert reasons == [
        "autor identificado solo por correo",
        "módulo sin disclosure_date",
        "nombre genérico",
        "posible varias personas u organizaciones",
    ]
    assert doc["implemented_parts"] == ["i"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Alice Example <alice@example.org>", "Alice Example"),
        ("Carol https://github.com/carol-example", "Carol"),
        ("Dan <dan-handle>", "Dan (dan-handle)"),
        ("only@example.org", ""),
        ("Zed ( <Zed (@zed)>", "Zed"),
        ("Yan [at] example [dot] org", ""),
    ],
)
def test_normalize_author(raw, expected):
    assert bta.normalize_author(raw) == expected


# --- esquema ------------------------------------------------------------------------------------


def test_generated_yaml_validates_schema():
    exposed = yaml.safe_load(bep.render(_build()))
    authors = yaml.safe_load(bta.render(bta.build(MSF, CUTOFF)))
    assert validate_exposed(exposed) == []
    assert validate_authors(authors) == []


def test_schema_rejects_bad_documents():
    exposed = yaml.safe_load(bep.render(_build()))
    exposed["inputs"][0]["sha256"] = "x"
    exposed["products"][0]["category"] = "toaster"
    exposed["products"][1]["cpe"] = []
    exposed["products"][1].pop("cpe_missing_reason", None)
    exposed["deployment_leg"]["products"] = [{"id": "deployment--x", "name": "x", "rank": 1}]
    errors = validate_exposed(exposed)
    assert any("hash" in e for e in errors) and any("categoría" in e for e in errors)
    assert any("sin CPE y sin motivo" in e for e in errors)
    assert any("deployment_leg" in e for e in errors)
    authors = yaml.safe_load(bta.render(bta.build(MSF, CUTOFF)))
    authors["authors"].append({"name": "x@example.org", "modules": []})
    assert validate_authors(authors)


# --- ningún nombre entra sin pasar por la regla -------------------------------------------------


def _check_products_follow_rule(doc: dict, kev: dict) -> None:
    cutoff = dt.date.fromisoformat(doc["cutoff_date"])
    start = months_before(cutoff, doc["window"]["months"])
    entries = {
        e["cveID"]: e
        for e in kev["vulnerabilities"]
        if start < dt.date.fromisoformat(e["dateAdded"][:10]) <= cutoff
    }
    for p in doc["products"]:
        own = [entries[c] for c in p["evidence"]["cves"]]  # KeyError si sale de fuera de la ventana
        pairs = {(e["vendorProject"].strip(), e["product"].strip()) for e in own}
        assert {(a["vendor"], a["product"]) for a in p["aliases"]} == pairs, p["id"]
        if p["category_source"] == "name":
            names = [*p["names"], *p["abbreviations"]] or [p["product"]]
            text = " | ".join(f"{p['vendor']} {n}" for n in names)
            assert bep.pick(bep.classify(text)) == p["category"], p["id"]
        else:
            hits = [
                p["category"]
                in bep.classify(f"{e['vulnerabilityName']} {e.get('shortDescription', '')}", False)
                for e in own
            ]
            assert 2 * sum(hits) >= len(own), p["id"]
        ev = p["evidence"]
        assert ev["vendor_category_entries"] >= max(doc["threshold"], len(ev["cves"])), p["id"]


def _check_authors_follow_rule(doc: dict, meta: dict) -> None:
    cutoff = dt.date.fromisoformat(doc["cutoff_date"])
    start = months_before(cutoff, doc["window"]["months"])
    by_name = {m["fullname"]: m for m in meta.values()}
    for a in doc["authors"]:
        assert a["modules"], a["name"]
        for fullname in a["modules"]:
            mod = by_name[fullname]
            assert mod["type"] == "exploit" and fullname.startswith("exploit/")
            assert start < dt.date.fromisoformat(mod["disclosure_date"][:10]) <= cutoff
            normalized = {bta.normalize_author(r).casefold() for r in mod["author"]}
            assert a["name"].casefold() in normalized, (a["name"], fullname)


def test_fixture_products_follow_rule():
    _check_products_follow_rule(_build(), json.loads(KEV))


def test_fixture_authors_follow_rule():
    _check_authors_follow_rule(bta.build(MSF, CUTOFF), json.loads(MSF))


def test_excluded_names_never_enter():
    names = {a["name"] for a in bta.build(MSF, CUTOFF)["authors"]}
    assert not names & {"Dave Old", "Eve Aux", "Frank Nodate", "Grace Future", "Unknown"}
    ids = set(_ids(_build()["products"]))
    assert not ids & {
        "soylent--widget",
        "globex--mail-relay",
        "initech--office-suite",
        "initech--multiple-products",
        "hooli--desktop-os",
        "umbrella--email-firewall",
    }


# --- listas commiteadas -------------------------------------------------------------------------


def _committed(name: str) -> dict:
    return yaml.safe_load((ROOT / "config" / name).read_text(encoding="utf-8"))


def test_committed_lists_validate_and_carry_hash():
    exposed = _committed("exposed-products.yaml")
    authors = _committed("trusted-exploit-authors.yaml")
    assert validate_exposed(exposed) == []
    assert validate_authors(authors) == []
    assert exposed["generator_version"] == bep.GENERATOR_VERSION
    assert exposed["criterion_version"] == bep.CRITERION_VERSION == 2
    assert exposed["rules_version"] == bep.RULES_VERSION == 2
    assert exposed["rules"] == {
        c: {"type": list(bep.TYPE_RULES[c]), "brand": list(bep.BRAND_RULES[c])}
        for c in bep.CATEGORIES
    }
    assert [i["name"] for i in exposed["inputs"]] == ["cisa-kev", "cvelistV5"]
    assert authors["generator_version"] == bta.GENERATOR_VERSION


def test_committed_products_have_cpe_or_reason():
    for p in _committed("exposed-products.yaml")["products"]:
        assert p["cpe"] or p["cpe_missing_reason"], p["id"]
        assert p["cna"], p["id"]


def test_committed_lists_have_no_emails():
    for name in ("exposed-products.yaml", "trusted-exploit-authors.yaml"):
        text = (ROOT / "config" / name).read_text(encoding="utf-8")
        assert not EMAIL_RE.search(text), name


def test_committed_lists_match_cached_inputs():
    """Si las entradas descargadas están en `.cache/`, las listas se regeneran idénticas."""
    checked = 0
    kev_path = ROOT / ".cache" / "lists" / "known_exploited_vulnerabilities.json"
    doc = _committed("exposed-products.yaml")
    if kev_path.exists():
        data = kev_path.read_bytes()
        cutoff = dt.date.fromisoformat(doc["cutoff_date"])
        records = cvelist.load_cached(bep.included_cves(data, cutoff))
        if bep.sha256_bytes(data) == doc["inputs"][0]["sha256"] and (
            cvelist.records_hash(records) == doc["inputs"][1]["sha256"]
        ):
            rendered = bep.render(bep.build(data, cutoff, records))
            assert rendered == (ROOT / "config" / "exposed-products.yaml").read_text("utf-8")
            _check_products_follow_rule(doc, json.loads(data))
            checked += 1
    msf_path = ROOT / ".cache" / "lists" / "modules_metadata_base.json"
    doc = _committed("trusted-exploit-authors.yaml")
    if msf_path.exists():
        data = msf_path.read_bytes()
        if bep.sha256_bytes(data) == doc["inputs"][0]["sha256"]:
            cutoff = dt.date.fromisoformat(doc["cutoff_date"])
            rendered = bta.render(bta.build(data, cutoff))
            assert rendered == (ROOT / "config" / "trusted-exploit-authors.yaml").read_text("utf-8")
            _check_authors_follow_rule(doc, json.loads(data))
            checked += 1
    if not checked:
        pytest.skip("sin entradas en .cache/lists con el hash de las listas commiteadas")
