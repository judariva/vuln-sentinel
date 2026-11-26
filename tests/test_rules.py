"""Motor de reglas A/B/C (PLAN.md §5, ADR-0012, ADR-0013, ADR-0022).

Todos los CVE, fabricantes, productos y cuentas de este fichero son FICTICIOS (CVE-2099-*). Las
listas son las de fixture (`tests/fixtures/lists/*.rules.yaml`), no las reales de `config/`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vs.feed.rights import PUBLIC, Audience, engine_for_feed, level_for_feed
from vs.model.schema import AlertLevelHistory, RuleEvaluation
from vs.rules.engine import RuleEngine, RulesConfig, assess
from vs.rules.exploit import ExploitRule, exploit_rules, poc_status
from vs.rules.impact import ImpactClass, impact_class, parse_cvss, rce_sin_auth
from vs.rules.levels import Level, final_level
from vs.rules.lists import ProductRef, load_lists, producto_expuesto
from vs.sources.base import Entity, LicenseClass, Record

FIXTURES = Path(__file__).parent / "fixtures" / "lists"
LISTS = load_lists(
    FIXTURES / "exposed-products.rules.yaml", FIXTURES / "trusted-exploit-authors.rules.yaml"
)
LICENSE = "example-commercial-license"
CLIENTS = Audience("client-1", frozenset(LicenseClass), frozenset({LICENSE}))

T0 = datetime(2099, 3, 1, 12, 0, tzinfo=UTC)  # carga inicial
T1 = T0 + timedelta(hours=1)  # primera ejecución tras la carga inicial
OLD = T0 - timedelta(days=400)

RCE_NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
RCE_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
DOS_NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


# -- constructores de registros (como los deja el ejecutor) -----------------------------------


def vuln(
    cve: str,
    *,
    published: datetime,
    cwe=("CWE-787",),
    cvss: str | None = RCE_NET,
    vendor: str | None = "Examplesoft",
    product: str | None = "Exampled",
    observed: datetime = T1,
    baseline: bool = False,
    source: str = "cvelistv5",
) -> Record:
    return Record(
        source=source,
        cve_id=cve,
        kind="vulnerability",
        license_class=LicenseClass.OPEN,
        entity=Entity.VULNERABILITY,
        value={
            "cna": "example-cna",
            "cvss_vector": cvss,
            "cwe": list(cwe),
            "vendor": vendor,
            "product": product,
            "withdrawn_at": None,
        },
        source_published_at=published,
        observed_at=observed,
        baseline=baseline,
    )


def affected(
    cve: str,
    *,
    vendor=None,
    product=None,
    cpe=None,
    purl=None,
    ecosystem=None,
    source="osv",
    observed=T1,
    baseline=False,
) -> Record:
    return Record(
        source=source,
        cve_id=cve,
        kind="affected_product",
        license_class=LicenseClass.OPEN,
        entity=Entity.AFFECTED_PRODUCT,
        value={
            "vendor": vendor,
            "product": product,
            "cpe": cpe,
            "purl": purl,
            "ecosystem": ecosystem,
            "ranges": [],
            "range_source": "osv",
        },
        source_published_at=observed,
        observed_at=observed,
        baseline=baseline,
    )


def sig(
    cve: str,
    kind: str,
    value: dict | None = None,
    *,
    source: str | None = None,
    observed: datetime = T1,
    baseline: bool = False,
    restricted: bool = False,
) -> Record:
    default_source = {
        "kev_cisa": "cisa-kev",
        "ssvc": "cvelistv5",
        "epss": "epss",
        "exploit": "exploits",
        "kev_vulncheck": "synthetic-restricted",
    }
    return Record(
        source=source or default_source.get(kind, "other"),
        cve_id=cve,
        kind=kind,
        license_class=LicenseClass.RESTRICTED if restricted else LicenseClass.OPEN,
        licensee=LICENSE if restricted else None,
        value=value or {},
        observed_at=observed,
        baseline=baseline,
    )


def kev(cve, **kw):
    return sig(cve, "kev_cisa", {"date_added": "2099-03-01"}, **kw)


def msf(cve, path, **kw):
    return sig(cve, "exploit", {"origin": "metasploit", "path": path}, **kw)


def edb(cve, kind, **kw):
    return sig(cve, "exploit", {"origin": "exploitdb", "type": kind, "edb_id": "99999"}, **kw)


def gh(cve, owner, suspicious=False, **kw):
    value = {"origin": "github", "owner": owner, "repo": f"{owner}/{cve}", "suspicious": suspicious}
    return sig(cve, "exploit", value, **kw)


def ssvc(cve, exploitation="none", technical_impact="partial", **kw):
    value = {"exploitation": exploitation, "technical_impact": technical_impact}
    return sig(cve, "ssvc", value, **kw)


SOURCES = ("cvelistv5", "cisa-kev", "epss", "exploits", "osv", "synthetic-restricted", "other")


def engine(audience=PUBLIC, recent_days=14, baselines_done=SOURCES) -> RuleEngine:
    e = engine_for_feed(audience, LISTS, RulesConfig(recent_days=recent_days))
    for s in baselines_done:
        e.complete_baseline(s, T0)
    return e


# -- impact_class (§5.2) ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cwes", "vector", "ti", "expected"),
    [
        (["CWE-787"], RCE_NET, None, ImpactClass.RCE),
        (
            ["CWE-416"],
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            None,
            "rce",
        ),
        (["CWE-78"], "AV:N/AC:L/Au:N/C:C/I:C/A:C", None, ImpactClass.RCE),  # CVSS v2
        (["CWE-787"], DOS_NET, None, ImpactClass.OTHER),  # memoria, pero solo DoS
        (["CWE-787"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H", None, ImpactClass.OTHER),
        (["CWE-20"], None, "total", ImpactClass.RCE),  # SSVC technical_impact = total
        (["CWE-287"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", None, "auth_bypass"),
        (["CWE-287"], "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", None, ImpactClass.OTHER),
        (["CWE-22"], "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", None, "arbitrary_rw"),
        (["CWE-918"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", None, "arbitrary_rw"),
        (["CWE-400"], DOS_NET, None, ImpactClass.OTHER),
        (["CWE-1333"], DOS_NET, "partial", ImpactClass.OTHER),
        (["CWE-200"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", None, ImpactClass.OTHER),
        (["NVD-CWE-Other"], RCE_NET, None, ImpactClass.OTHER),
        ([], None, None, ImpactClass.OTHER),
    ],
)
def test_impact_class_table(cwes, vector, ti, expected):
    assert impact_class(cwes, vector, ti) == ImpactClass(expected)


def test_impact_class_first_match_wins():
    # CWE de RCE y de auth_bypass a la vez: gana rce (orden de la tabla).
    assert impact_class(["CWE-287", "CWE-94"], RCE_NET) is ImpactClass.RCE


def test_rce_sin_auth():
    assert rce_sin_auth(ImpactClass.RCE, RCE_NET)
    assert not rce_sin_auth(ImpactClass.RCE, RCE_LOCAL)
    assert not rce_sin_auth(ImpactClass.RCE, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
    assert not rce_sin_auth(ImpactClass.AUTH_BYPASS, RCE_NET)
    # CVSS v2 no tiene UI: no se presume UI:N.
    assert not rce_sin_auth(ImpactClass.RCE, "AV:N/AC:L/Au:N/C:C/I:C/A:C")


def test_parse_cvss_garbage():
    assert parse_cvss("esto no es un vector").av is None
    assert parse_cvss(None) == parse_cvss("")


# -- producto_expuesto ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ref",
    [
        ProductRef("examplesoft", "EXAMPLED"),
        ProductRef("Example Software Inc.", "Exampled  Server"),  # alias de otro CNA
        ProductRef(cpe="cpe:2.3:a:examplesoft:exampled:1.2.3:*:*:*:*:*:*:*"),
        ProductRef(purl="pkg:generic/exampled@1.2.3"),
        ProductRef("TunnelCorp", "TunnelGate"),
    ],
)
def test_exposed_matches(ref):
    assert producto_expuesto([ref], LISTS) is not None


@pytest.mark.parametrize(
    "ref",
    [
        ProductRef("PendingVendor", "PendingGW"),  # needs_review no decide
        ProductRef("Examplesoft", "Other product"),
        ProductRef(cpe="cpe:2.3:a:examplesoft:exampled_other:1.0"),  # prefijo, no subcadena
        ProductRef(purl="pkg:generic/exampled-tools@1.0"),
        ProductRef("Linux", "Linux Kernel"),
    ],
)
def test_exposed_does_not_match(ref):
    assert producto_expuesto([ref], LISTS) is None


def test_exposed_category():
    assert producto_expuesto([ProductRef("TunnelCorp", "TunnelGate")], LISTS).category == "vpn"


# -- exploit funcional (§5.3) -----------------------------------------------------------------


def _rules(*values, ssvc_e=None):
    return exploit_rules(values, ssvc_e, LISTS)


def test_e1_only_exploit_modules():
    assert _rules({"origin": "metasploit", "path": "exploit/linux/http/x"}) == [ExploitRule.E1]
    assert _rules({"origin": "metasploit", "path": "auxiliary/dos/http/x"}) == []
    assert _rules({"origin": "metasploit", "path": "auxiliary/scanner/http/x"}) == []


def test_e2_not_dos():
    assert _rules({"origin": "exploitdb", "type": "remote"}) == [ExploitRule.E2]
    assert _rules({"origin": "exploitdb", "type": "webapps"}) == [ExploitRule.E2]
    assert _rules({"origin": "exploitdb", "type": "dos"}) == []
    assert _rules({"origin": "exploitdb", "type": "DoS"}) == []


def test_e3_ssvc_poc():
    assert _rules(ssvc_e="poc") == [ExploitRule.E3]
    assert _rules(ssvc_e="none") == []


def test_e4_trusted_author_and_reference():
    assert _rules({"origin": "github", "owner": "Example-Research"}) == [ExploitRule.E4]
    assert _rules({"origin": "github", "owner": "jdoe-example"}) == [ExploitRule.E4]
    # Un autor con `github` solo casa por la cuenta, no por el nombre.
    assert _rules({"origin": "github", "owner": "Example Research Labs"}) == []
    assert _rules({"origin": "github", "owner": "random-person"}) == []
    assert _rules({"origin": "github", "owner": "Untrusted Person"}) == []  # needs_review
    assert _rules({"origin": "reference", "by": "nvd", "tags": ["Exploit"]}) == [ExploitRule.E4]
    assert _rules({"origin": "reference", "by": "cve_record", "tags": ["exploit"]}) == ["E4"]
    assert _rules({"origin": "reference", "by": "blog", "tags": ["exploit"]}) == []
    assert _rules({"origin": "reference", "by": "nvd", "tags": ["patch"]}) == []


def test_poc_status():
    trusted = {"origin": "github", "owner": "example-research"}
    assert poc_status(trusted, LISTS) is None
    assert poc_status({"origin": "github", "owner": "nobody"}, LISTS) == "poc_unverified"
    assert poc_status({**trusted, "suspicious": True}, LISTS) == "poc_suspicious"
    assert _rules({**trusted, "suspicious": True}) == []


# -- assess: niveles (§5.2) -------------------------------------------------------------------

CVE = "CVE-2099-0100"


def _assess(*records):
    return assess(CVE, records, LISTS)


def test_a_from_kev_or_ssvc_active():
    old = vuln(CVE, published=OLD, product="Unrelated", cwe=["CWE-400"], cvss=DOS_NET)
    a = _assess(old, kev(CVE))
    assert a.level is Level.A
    assert a.reason == ("A.kev_cisa",)
    assert _assess(old, ssvc(CVE, "active")).level is Level.A
    assert _assess(old, sig(CVE, "vendor_exploited")).level is Level.A


def test_b_exposed_impact_exploit():
    a = _assess(vuln(CVE, published=T1), gh(CVE, "example-research"))
    assert a.level is Level.B
    assert a.reason == ("B.exposed_product:web-proxy", "B.impact:rce", "B.exploit:E4")
    assert a.exploit_rule is ExploitRule.E4


def test_c_exposed_rce_unauth_without_exploit():
    a = _assess(vuln(CVE, published=T1))
    assert a.level is Level.C
    assert a.reason == ("C.exposed_product:web-proxy", "C.impact:rce", "C.rce_unauth")


def test_untrusted_poc_does_not_raise():
    assert _assess(vuln(CVE, published=T1), gh(CVE, "random-person")).level is Level.C


def test_not_exposed_is_none():
    a = _assess(vuln(CVE, published=T1, vendor="Other", product="Other"), msf(CVE, "exploit/x"))
    assert a.level is Level.NONE


def test_auth_bypass_without_exploit_is_not_c():
    v = vuln(CVE, published=T1, cwe=["CWE-306"], cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:L/I:L/A:N")
    assert _assess(v).level is Level.NONE
    assert _assess(v, edb(CVE, "remote")).level is Level.B


def test_dos_exploit_on_exposed_product_is_not_b():
    """R3, ADR-0013: DoS con exploit (auxiliary/dos, Exploit-DB dos) en un producto expuesto."""
    v = vuln(CVE, published=T1, cwe=["CWE-400"], cvss=DOS_NET)
    a = _assess(v, msf(CVE, "auxiliary/dos/http/exampled_dos"), edb(CVE, "dos"))
    assert a.exposed
    assert a.impact_class is ImpactClass.OTHER
    assert a.level is Level.NONE


def test_dos_module_on_rce_cve_does_not_count_as_exploit():
    v = vuln(CVE, published=T1)  # rce sin autenticación
    a = _assess(v, msf(CVE, "auxiliary/dos/http/exampled_dos"), edb(CVE, "dos"))
    assert a.level is Level.C  # sigue en C: el exploit de DoS no corresponde al impacto


class FakeE5:
    def __init__(self, answer: bool):
        self.answer = answer
        self.calls = 0

    def confirms(self, cve_id, signal_value):
        self.calls += 1
        return self.answer


def test_e5_only_lifts_c_to_b():
    v = vuln(CVE, published=T1)
    poc = gh(CVE, "random-person")
    yes = FakeE5(True)
    a = assess(CVE, [v, poc], LISTS, yes)
    assert (a.level, a.exploit_rule) == (Level.B, ExploitRule.E5)
    assert assess(CVE, [v, poc], LISTS, FakeE5(False)).level is Level.C
    # Fuera de C (auth_bypass) no se consulta.
    ab = vuln(CVE, published=T1, cwe=["CWE-306"], cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:L/I:L/A:N")
    never = FakeE5(True)
    assert assess(CVE, [ab, poc], LISTS, never).level is Level.NONE
    assert never.calls == 0


# -- carga inicial y «nuevo» (§5.1, ADR-0012) -------------------------------------------------


def _initial_load() -> list[Record]:
    """Carga inicial con de todo: KEV, SSVC active, exploits y CVE recientes y antiguas."""
    recs: list[Record] = []
    for n in range(40):
        cve = f"CVE-2099-{1000 + n:04d}"
        published = T0 - timedelta(days=n % 3) if n % 2 else OLD  # la mitad, recientes
        recs.append(vuln(cve, published=published, observed=T0, baseline=True))
        recs.append(kev(cve, observed=T0, baseline=True) if n % 4 == 0 else ssvc(cve, "poc"))
        recs.append(gh(cve, "example-research", observed=T0, baseline=True))
        recs.append(sig(cve, "epss", {"epss": 0.9}, observed=T0, baseline=True))
    return [r if r.baseline else _as_baseline(r) for r in recs]


def _as_baseline(r: Record) -> Record:
    from dataclasses import replace

    return replace(r, observed_at=T0, baseline=True)


def test_initial_load_gives_zero_alerts():
    e = engine(baselines_done=())  # nada tiene la carga inicial cerrada
    res = e.ingest(_initial_load(), now=T0)
    assert res.evaluations  # se evalúa todo
    assert {ev.computed_level for ev in res.evaluations} >= {Level.A, Level.B}
    assert res.alerts == []
    assert not any(ev.eligible for ev in res.evaluations)
    assert all(ev.result_level is Level.NONE for ev in res.evaluations)
    assert all(e.level(ev.cve_id) is Level.NONE for ev in res.evaluations)


def test_new_source_gives_zero_alerts():
    e = engine(baselines_done=("cvelistv5",))
    old = [vuln(f"CVE-2099-2{n:03d}", published=OLD, observed=T0, baseline=True) for n in range(30)]
    recent = vuln("CVE-2099-2999", published=T1 - timedelta(days=1), observed=T1)
    # Solo alerta la reciente, que no es de carga inicial.
    assert {c.cve_id for c in e.ingest([*old, recent], now=T1).alerts} == {"CVE-2099-2999"}
    later = T1 + timedelta(hours=1)
    # Fuente nueva: su primera ejecución es de carga inicial (KEV, exploits, SSVC active).
    first_run = [kev(r.cve_id, observed=later, baseline=True) for r in old]
    first_run += [msf(r.cve_id, "exploit/x", observed=later, baseline=True) for r in old]
    first_run += [kev("CVE-2099-2999", observed=later, baseline=True)]
    res = e.ingest(first_run, now=later)
    assert res.alerts == []
    e.complete_baseline("cisa-kev", later)
    e.complete_baseline("exploits", later)
    # Repetir lo mismo en la ejecución siguiente tampoco alerta: no es nuevo.
    again = [kev(r.cve_id, observed=later + timedelta(minutes=15)) for r in old]
    assert e.ingest(again, now=later + timedelta(minutes=15)).alerts == []


def test_new_signal_on_old_cve_after_baseline_alerts():
    e = engine(baselines_done=())
    old = "CVE-2099-3000"
    e.ingest([vuln(old, published=OLD, observed=T0, baseline=True)], now=T0)
    for s in SOURCES:
        e.complete_baseline(s, T0)
    res = e.ingest([kev(old, observed=T1)], now=T1)
    assert [(c.cve_id, c.level_from, c.level_to) for c in res.alerts] == [
        (old, Level.NONE, Level.A)
    ]
    ev = res.evaluations[0]
    assert ev.eligible and ev.result_level is Level.A
    assert ev.trigger is not None and ev.trigger.kind == "kev_cisa"


def test_irrelevant_new_signal_on_old_cve_does_not_alert():
    """El EPSS diario es una señal nueva, pero no sube el nivel: una CVE antigua no alerta."""
    e = engine(baselines_done=())
    old = "CVE-2099-3001"
    e.ingest(
        [
            vuln(old, published=OLD, observed=T0, baseline=True),
            kev(old, observed=T0, baseline=True),
        ],
        now=T0,
    )
    for s in SOURCES:
        e.complete_baseline(s, T0)
    res = e.ingest([sig(old, "epss", {"epss": 0.97}, observed=T1)], now=T1)
    assert res.alerts == []
    assert res.evaluations[0].computed_level is Level.A  # es A, pero ya lo era en la carga
    assert not res.evaluations[0].eligible


def test_recent_cve_goes_c_then_b():
    e = engine()
    cve = "CVE-2099-3002"
    r1 = e.ingest([vuln(cve, published=T1)], now=T1)
    assert [(c.level_from, c.level_to) for c in r1.alerts] == [(Level.NONE, Level.C)]
    t2 = T1 + timedelta(minutes=20)
    r2 = e.ingest([gh(cve, "example-research", observed=t2)], now=t2)
    assert [(c.level_from, c.level_to) for c in r2.alerts] == [(Level.C, Level.B)]
    assert r2.alerts[0].reason[-1] == "B.exploit:E4"
    assert e.level(cve) is Level.B


def test_recent_window_is_configurable():
    cve = "CVE-2099-3003"
    published = T1 - timedelta(days=10)
    assert engine(recent_days=14).ingest([vuln(cve, published=published)], now=T1).alerts
    assert not engine(recent_days=7).ingest([vuln(cve, published=published)], now=T1).alerts


def test_dos_with_exploit_on_exposed_product_does_not_alert_b():
    e = engine()
    cve = "CVE-2099-3004"
    res = e.ingest(
        [
            vuln(cve, published=T1, cwe=["CWE-400"], cvss=DOS_NET),
            msf(cve, "auxiliary/dos/http/exampled_dos"),
            edb(cve, "dos"),
        ],
        now=T1,
    )
    assert res.evaluations[0].eligible and res.evaluations[0].exposed
    assert res.alerts == []
    assert e.level(cve) is Level.NONE


# -- ruido: una USN de kernel con cientos de CVE ----------------------------------------------


def test_kernel_usn_noise_only_kev_alerts():
    """Sintético: un aviso de Ubuntu (USN) del kernel cita 300 CVE recientes. Solo alertan las
    que están en KEV."""
    e = engine()
    cves = [f"CVE-2099-{40000 + n}" for n in range(300)]
    recs: list[Record] = []
    for i, cve in enumerate(cves):
        recs.append(
            vuln(
                cve,
                published=T1 - timedelta(days=i % 10),
                cwe=["CWE-416"] if i % 2 else ["CWE-401"],
                cvss=RCE_LOCAL,
                vendor="Linux",
                product="Linux",
            )
        )
        recs.append(
            affected(
                cve,
                product="linux",
                purl="pkg:deb/ubuntu/linux@6.8.0-99.99",
                ecosystem="Ubuntu:24.04:LTS",
            )
        )
        recs.append(ssvc(cve, "none", "partial"))
        recs.append(sig(cve, "epss", {"epss": 0.0004}))
    in_kev = {cves[7], cves[123]}
    recs += [kev(c) for c in sorted(in_kev)]
    res = e.ingest(recs, now=T1)
    assert len(res.evaluations) == 300
    assert {c.cve_id for c in res.alerts} == in_kev
    assert all(c.level_to is Level.A for c in res.alerts)


# -- monotonía (CTL-001) ----------------------------------------------------------------------

_LEVELS = st.sampled_from(list(Level))


@given(det=_LEVELS, ai=st.none() | _LEVELS, pub=_LEVELS)
def test_final_level_never_below_inputs(det, ai, pub):
    fl = final_level(det, ai, pub)
    assert fl.level >= det and fl.level >= pub
    if ai is not None:
        assert fl.level >= ai
        assert fl.blocked_downgrade == (ai < max(det, pub))
    else:
        assert not fl.blocked_downgrade


_MCVE = "CVE-2099-5000"


def _record_strategy():
    cvss = st.sampled_from([RCE_NET, RCE_LOCAL, DOS_NET, None])
    cwe = st.sampled_from([["CWE-787"], ["CWE-400"], ["CWE-287"], ["CWE-22"], []])
    product = st.sampled_from(["Exampled", "Other"])
    published = st.sampled_from([OLD, T1 - timedelta(days=3)])
    vulns = st.builds(
        lambda c, w, p, pub, b: vuln(_MCVE, published=pub, cwe=w, cvss=c, product=p, baseline=b),
        cvss,
        cwe,
        product,
        published,
        st.booleans(),
    )
    signals = st.one_of(
        st.builds(lambda b: kev(_MCVE, baseline=b), st.booleans()),
        st.builds(
            lambda e, t, b: ssvc(_MCVE, e, t, baseline=b),
            st.sampled_from(["none", "poc", "active"]),
            st.sampled_from(["partial", "total"]),
            st.booleans(),
        ),
        st.builds(lambda p: msf(_MCVE, p), st.sampled_from(["exploit/x", "auxiliary/dos/x"])),
        st.builds(lambda k: edb(_MCVE, k), st.sampled_from(["remote", "dos"])),
        st.builds(lambda o: gh(_MCVE, o), st.sampled_from(["example-research", "nobody"])),
        st.builds(lambda s: sig(_MCVE, "epss", {"epss": s}), st.floats(0, 1)),
        st.builds(lambda: sig(_MCVE, "kev_vulncheck", restricted=True)),
    )
    return st.one_of(vulns, signals)


@settings(max_examples=150, deadline=None)
@given(
    batches=st.lists(st.lists(_record_strategy(), min_size=1, max_size=4), min_size=1, max_size=8),
    public=st.booleans(),
)
def test_published_level_never_drops(batches, public):
    e = engine(PUBLIC if public else CLIENTS)
    now = T1
    seen = Level.NONE
    for batch in batches:
        now += timedelta(minutes=5)
        stamped = [_restamp(r, now) for r in batch]
        res = e.ingest(stamped, now=now)
        assert e.level(_MCVE) >= seen
        seen = e.level(_MCVE)
        for c in res.changes:
            assert c.decided_by == "rules" and c.level_to > c.level_from
    assert all(c.level_to > c.level_from for c in e.history)


def _restamp(r: Record, now: datetime) -> Record:
    from dataclasses import replace

    return replace(r, observed_at=now)


@settings(max_examples=150, deadline=None)
@given(
    base=st.lists(_record_strategy(), max_size=5),
    extra=st.lists(
        _record_strategy().filter(lambda r: r.entity is Entity.SIGNAL), min_size=1, max_size=4
    ),
)
def test_adding_signals_never_lowers_assessment(base, extra):
    """Con los mismos hechos de la CVE, más señales nunca dan un nivel menor."""
    before = assess(_MCVE, base, LISTS).level
    after = assess(_MCVE, [*base, *extra], LISTS).level
    assert after >= before


def test_ai_cannot_lower_level():
    e = engine()
    cve = "CVE-2099-5001"
    e.ingest([vuln(cve, published=T1), gh(cve, "example-research")], now=T1)
    assert e.level(cve) is Level.B
    change, blocked = e.apply_ai(cve, Level.NONE, ["ai.says_benign"], now=T1)
    assert change is None and blocked
    assert e.level(cve) is Level.B
    change, blocked = e.apply_ai(cve, Level.A, ["A.ai_cited_vendor_exploited"], now=T1)
    assert change is not None and change.decided_by == "ai" and not blocked
    assert e.level(cve) is Level.A


def test_rules_cannot_lower_level_after_facts_change():
    e = engine()
    cve = "CVE-2099-5002"
    e.ingest([vuln(cve, published=T1)], now=T1)
    assert e.level(cve) is Level.C
    t2 = T1 + timedelta(minutes=5)
    # El CNA corrige el CVSS a solo DoS: las reglas darían NONE, el nivel publicado se queda.
    res = e.ingest([vuln(cve, published=T1, cvss=DOS_NET, observed=t2)], now=t2)
    assert res.evaluations[0].computed_level is Level.NONE
    assert res.changes == []
    assert e.level(cve) is Level.C


def test_manual_downgrade_is_recorded_and_needs_person_and_reason():
    e = engine()
    cve = "CVE-2099-5003"
    e.ingest([vuln(cve, published=T1)], now=T1)
    with pytest.raises(ValueError):
        e.manual_set_level(cve, Level.NONE, "rules", ["x"], now=T1)
    with pytest.raises(ValueError):
        e.manual_set_level(cve, Level.NONE, "ai", ["x"], now=T1)
    with pytest.raises(ValueError):
        e.manual_set_level(cve, Level.NONE, "juan", [], now=T1)
    change = e.manual_set_level(
        cve, Level.NONE, "juan", ["falso positivo: producto no expuesto"], T1
    )
    assert (change.level_from, change.level_to, change.decided_by) == (Level.C, Level.NONE, "juan")
    assert e.history[-1] is change
    assert e.level(cve) is Level.NONE


# -- nivel por feed según derechos (ADR-0022) -------------------------------------------------


def test_restricted_only_a_is_not_a_in_public_feed():
    cve = "CVE-2099-6000"
    recs = [
        vuln(cve, published=T1),  # expuesto, rce sin autenticación: C con datos abiertos
        sig(cve, "kev_vulncheck", restricted=True),
    ]
    assert level_for_feed(recs, CLIENTS, LISTS) is Level.A
    assert level_for_feed(recs, PUBLIC, LISTS) is Level.C

    public, clients = engine(PUBLIC), engine(CLIENTS)
    rp, rc = public.ingest(recs, now=T1), clients.ingest(recs, now=T1)
    assert rp.dropped_by_rights == 1 and rc.dropped_by_rights == 0
    assert public.level(cve) is Level.C
    assert clients.level(cve) is Level.A
    assert all(r.license_class is LicenseClass.OPEN for r in public.records(cve))
    assert "A.kev_vulncheck" not in rp.alerts[0].reason


def test_restricted_signal_later_does_not_raise_public():
    cve = "CVE-2099-6001"
    public = engine(PUBLIC)
    public.ingest([vuln(cve, published=OLD, observed=T0, baseline=True)], now=T0)
    res = public.ingest([sig(cve, "kev_vulncheck", restricted=True)], now=T1)
    assert res.alerts == [] and res.evaluations == []
    assert public.level(cve) is Level.NONE


# -- filas del modelo -------------------------------------------------------------------------


def _columns(table) -> set[str]:
    return {c.name for c in table.__table__.columns} - {"id"}


def test_evaluation_row_matches_model():
    e = engine()
    cve = "CVE-2099-7000"
    res = e.ingest([vuln(cve, published=T1), gh(cve, "example-research")], now=T1)
    row = res.evaluations[0].to_row(trigger_signal_id=None)
    assert set(row) == _columns(RuleEvaluation)
    assert row["result_level"] == "B" and row["exploit_rule"] == "E4"
    assert row["impact_class"] == "rce" and row["eligible"] and row["exposed"]
    assert set(res.changes[0].to_row()) == _columns(AlertLevelHistory)
    assert res.changes[0].to_row()["level_from"] == "none"


def test_one_evaluation_per_cve_per_batch_and_deduplication():
    e = engine()
    cves = [f"CVE-2099-71{n:02d}" for n in range(5)]
    batch = [vuln(c, published=T1) for c in cves] + [kev(c) for c in cves]
    assert len(e.ingest(batch, now=T1).evaluations) == 5
    # El mismo lote otra vez: nada nuevo, nada que evaluar.
    assert e.ingest(batch, now=T1 + timedelta(minutes=5)).evaluations == []
