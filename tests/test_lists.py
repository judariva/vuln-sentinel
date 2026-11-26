"""Generadores de listas (F1a-0, R7): deterministas, con esquema y sin nombres fuera de la regla."""

import datetime as dt
import json
import random
from pathlib import Path

import pytest
import yaml

from vs.lists import build_exposed_products as bep
from vs.lists import build_trusted_authors as bta
from vs.lists.common import months_before
from vs.lists.schema import EMAIL_RE, validate_authors, validate_exposed

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "lists"
CUTOFF = dt.date(2026, 11, 26)
KEV = (FIX / "kev_small.json").read_bytes()
MSF = (FIX / "msf_small.json").read_bytes()


def _ids(items):
    return [i["id"] for i in items]


# --- determinismo -------------------------------------------------------------------------------


def test_exposed_is_deterministic():
    assert bep.render(bep.build(KEV, CUTOFF)) == bep.render(bep.build(KEV, CUTOFF))


def test_exposed_ignores_input_order():
    data = json.loads(KEV)
    random.Random(7).shuffle(data["vulnerabilities"])  # noqa: S311 (orden de prueba, no cripto)
    shuffled = json.dumps(data).encode()
    a, b = bep.build(KEV, CUTOFF), bep.build(shuffled, CUTOFF)
    for key in ("products", "needs_review", "below_threshold", "stats"):
        assert a[key] == b[key]
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
    doc = bep.build(KEV, CUTOFF)
    assert _ids(doc["products"]) == ["acme--secure-access", "acme--vpn-gateway"]
    assert _ids(doc["below_threshold"]) == ["globex--mail-relay"]
    assert _ids(doc["needs_review"]) == [
        "hooli--desktop-os",
        "initech--office-suite",
        "umbrella--email-firewall",
    ]
    assert doc["stats"]["ignored"] == 1  # soylent--widget
    vpn = doc["products"][1]
    assert vpn["vendor"] == "Acme" and vpn["product"] == "VPN Gateway"
    # fuera de ventana (2020) y posterior al corte (2026-12-01) no cuentan
    assert vpn["evidence"]["cves"] == ["CVE-2024-90003", "CVE-2025-90002", "CVE-2026-90001"]
    assert vpn["evidence"]["vendor_category_entries"] == 4
    assert {"vendor": "ACME", "product": "VPN gateway"} in vpn["aliases"]


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
    exposed = yaml.safe_load(bep.render(bep.build(KEV, CUTOFF)))
    authors = yaml.safe_load(bta.render(bta.build(MSF, CUTOFF)))
    assert validate_exposed(exposed) == []
    assert validate_authors(authors) == []


def test_schema_rejects_bad_documents():
    exposed = yaml.safe_load(bep.render(bep.build(KEV, CUTOFF)))
    exposed["inputs"][0]["sha256"] = "x"
    exposed["products"][0]["category"] = "toaster"
    errors = validate_exposed(exposed)
    assert any("hash" in e for e in errors) and any("categoría" in e for e in errors)
    authors = yaml.safe_load(bta.render(bta.build(MSF, CUTOFF)))
    authors["authors"].append({"name": "x@example.org", "modules": []})
    assert validate_authors(authors)


# --- ningún nombre entra sin pasar por la regla -------------------------------------------------


def _check_products_follow_rule(doc: dict, kev: dict) -> None:
    cutoff = dt.date.fromisoformat(doc["cutoff_date"])
    start = months_before(cutoff, doc["window"]["months"])
    entries = [
        e
        for e in kev["vulnerabilities"]
        if start < dt.date.fromisoformat(e["dateAdded"][:10]) <= cutoff
    ]
    for p in doc["products"]:
        aliases = {(a["vendor"], a["product"]) for a in p["aliases"]}
        own = [e for e in entries if (e["vendorProject"].strip(), e["product"].strip()) in aliases]
        assert own, f"{p['id']}: no sale de ninguna entrada de KEV en la ventana"
        assert sorted(e["cveID"] for e in own) == p["evidence"]["cves"]
        cats = [
            bep.classify(f"{e['vendorProject']} {e['product']} {e['vulnerabilityName']}")
            for e in own
        ]
        assert {c for cs in cats for c in cs} == {p["category"]}, p["id"]
        assert 2 * sum(p["category"] in cs for cs in cats) >= len(own), p["id"]
        assert p["evidence"]["vendor_category_entries"] >= doc["threshold"], p["id"]


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
    _check_products_follow_rule(bep.build(KEV, CUTOFF), json.loads(KEV))


def test_fixture_authors_follow_rule():
    _check_authors_follow_rule(bta.build(MSF, CUTOFF), json.loads(MSF))


def test_excluded_names_never_enter():
    names = {a["name"] for a in bta.build(MSF, CUTOFF)["authors"]}
    assert not names & {"Dave Old", "Eve Aux", "Frank Nodate", "Grace Future", "Unknown"}
    ids = set(_ids(bep.build(KEV, CUTOFF)["products"]))
    assert not ids & {"soylent--widget", "globex--mail-relay", "initech--office-suite"}


# --- listas commiteadas -------------------------------------------------------------------------


def _committed(name: str) -> dict:
    return yaml.safe_load((ROOT / "config" / name).read_text(encoding="utf-8"))


def test_committed_lists_validate_and_carry_hash():
    exposed = _committed("exposed-products.yaml")
    authors = _committed("trusted-exploit-authors.yaml")
    assert validate_exposed(exposed) == []
    assert validate_authors(authors) == []
    assert exposed["generator_version"] == bep.GENERATOR_VERSION
    assert exposed["rules_version"] == bep.RULES_VERSION
    assert exposed["rules"] == {k: list(v) for k, v in bep.CATEGORY_RULES.items()}
    assert authors["generator_version"] == bta.GENERATOR_VERSION


def test_committed_lists_have_no_emails():
    for name in ("exposed-products.yaml", "trusted-exploit-authors.yaml"):
        text = (ROOT / "config" / name).read_text(encoding="utf-8")
        assert not EMAIL_RE.search(text), name


def test_committed_lists_match_cached_inputs():
    """Si la entrada descargada está en `.cache/`, la lista commiteada se regenera idéntica."""
    pairs = [
        (bep, "known_exploited_vulnerabilities.json", "exposed-products.yaml"),
        (bta, "modules_metadata_base.json", "trusted-exploit-authors.yaml"),
    ]
    checked = 0
    for mod, cached, committed in pairs:
        path = ROOT / ".cache" / "lists" / cached
        doc = _committed(committed)
        if not path.exists():
            continue
        data = path.read_bytes()
        if bep.sha256_bytes(data) != doc["inputs"][0]["sha256"]:
            continue
        cutoff = dt.date.fromisoformat(doc["cutoff_date"])
        rendered = mod.render(mod.build(data, cutoff))
        assert rendered == (ROOT / "config" / committed).read_text(encoding="utf-8")
        if mod is bep:
            _check_products_follow_rule(doc, json.loads(data))
        else:
            _check_authors_follow_rule(doc, json.loads(data))
        checked += 1
    if not checked:
        pytest.skip("sin entradas en .cache/lists con el hash de las listas commiteadas")
