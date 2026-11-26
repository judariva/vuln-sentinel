"""Reconstrucción de nginx2root: prueba de aceptación R6 (PLAN.md §6 y §13, T12).

Es una **reconstrucción**: los snapshots de `tests/fixtures/nginx2root/` son datos publicados
(versiones de cvelistV5 por commit, el historial de cambios de NVD, el catálogo KEV de la fecha y
metadatos de GitHub), no grabaciones de lo que devolvían las API el 18/11. La prueba real es el
siguiente caso en vivo.

Reloj simulado: pasos de 5 min de las 15:00Z a las 18:00Z del 18/11. En cada paso, cada fuente ve
solo lo que estaba publicado a esa hora. El pipeline es el real: conectores (`vs.sources`) con un
transporte simulado → ejecutor (`run_source`, fail-closed, carga inicial) → motor de reglas con las
listas de `config/` → publicador del feed firmado.

Dos piezas no existen en el código y se emulan aquí, sin tocar reglas ni listas:
- **NVD**: no hay conector. `NvdReconstructionConnector` reconstruye la vista de NVD en cada paso a
  partir de su historial de cambios y emite la señal `exploit` con `origin = reference` y
  `by = nvd` del contrato de `vs.rules.exploit`.
- **Búsqueda de GitHub**: el conector es el real; lo que se simula es su respuesta. Cuándo pasó el
  repositorio a público es UNKNOWN (PLAN §6), así que nunca está visible.

La traza legible (`docs/journey/nginx2root-reconstruccion.md`) la genera esta prueba. Para
regenerarla: `VS_WRITE_TRACE=1 uv run pytest tests/test_nginx2root_reconstruction.py`.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from functools import cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from vs.feed.config import load_feed_config
from vs.feed.publish import FeedPublisher
from vs.feed.rights import PUBLIC, engine_for_feed
from vs.feed.sign import LocalDevSigner, verify_detached
from vs.rules.engine import RulesConfig, assess
from vs.rules.impact import rce_sin_auth
from vs.rules.levels import Level
from vs.rules.lists import RuleLists, load_lists, parse_lists
from vs.sources.base import Connector, Entity, LicenseClass, Record
from vs.sources.cisa_kev import DEFAULT_URL as KEV_URL
from vs.sources.cisa_kev import CisaKevConnector
from vs.sources.cvelistv5 import DEFAULT_DELTA_LOG_URL, CveListV5Connector
from vs.sources.github import RateLimiter
from vs.sources.github_search import GithubSearchConnector
from vs.sources.http import Response, get_json, parse_ts
from vs.sources.run import RunStatus, run_source

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "nginx2root"
TRACE_DOC = ROOT / "docs" / "journey" / "nginx2root-reconstruccion.md"
BEGIN, END = "<!-- traza:inicio -->", "<!-- traza:fin -->"

CVE_A = "CVE-2026-123007"
CVE_B = "CVE-2026-123633"
CVES = (CVE_A, CVE_B)
START = datetime(2026, 11, 18, 15, 0, tzinfo=UTC)
STOP = datetime(2026, 11, 18, 18, 0, tzinfo=UTC)
STEP = timedelta(minutes=5)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEARCH_API = "https://api.github.com/search/repositories"
# Cadencias (PLAN §4): cvelistV5 cada 5 min y KEV cada 15. NVD es «bajo demanda»: aquí se consulta
# en cada paso para darle su oportunidad. La búsqueda, en cada paso, solo para candidatos B/C.
KEV_EVERY = timedelta(minutes=15)


def load(*parts: str) -> Any:
    return json.loads(FIX.joinpath(*parts).read_text(encoding="utf-8"))


def ts(value: str) -> datetime:
    return parse_ts(value, "fixture")


def hhmm(t: datetime) -> str:
    return t.strftime("%H:%M")


# -- listas -------------------------------------------------------------------------------------

CONFIG_LISTS = load_lists(
    ROOT / "config" / "exposed-products.yaml", ROOT / "config" / "trusted-exploit-authors.yaml"
)


def counterfactual_lists() -> RuleLists:
    """Diagnóstico, NO el resultado: las listas de `config/` más un producto con los pares del CNA.

    Responde a «¿bastaría con que la lista casara?». No cambia ninguna lista del repo.
    """
    exposed = {
        "products": [
            {
                "id": "contrafactual--f5-nginx",
                "category": "web-proxy",
                "vendor": "F5",
                "product": "NGINX Open Source",
                "aliases": [{"vendor": "F5", "product": "NGINX Plus"}],
            }
        ]
    }
    extra = parse_lists(exposed, None)
    return RuleLists(
        exposed=tuple(sorted((*CONFIG_LISTS.exposed, *extra.exposed), key=lambda e: e.id)),
        authors=CONFIG_LISTS.authors,
    )


# -- lo que cada fuente tenía publicado a cada hora ---------------------------------------------


class Snapshots:
    """Vista de cada fuente a una hora dada, a partir de los fixtures."""

    def __init__(self) -> None:
        self.delta_log = load("cvelistv5", "deltaLog.json")
        self.versions = {
            cve: [(ts(v["committed_at"]), load("cvelistv5", v["file"])) for v in items]
            for cve, items in load("cvelistv5", "versions.json").items()
        }
        self.kev = load("cisa-kev", "kev-2026.11.17.json")
        self.nvd_history = load("nvd", "CVE-2026-123007.history.json")["cveChanges"]
        self.repo = load("github", "sfewer-r7.CVE-2026-123007.json")

    def delta_log_at(self, now: datetime) -> list[dict[str, Any]]:
        return [e for e in self.delta_log if ts(e["fetchTime"]) <= now]

    def record_at(self, cve: str, now: datetime) -> dict[str, Any] | None:
        seen = [rec for when, rec in self.versions.get(cve, []) if when <= now]
        return seen[-1] if seen else None

    def nvd_at(self, cve: str, now: datetime) -> dict[str, Any] | None:
        """El registro de NVD reconstruido con su historial: referencias y etiquetas a esa hora."""
        if cve != CVE_A:
            return None  # solo se reconstruye el NVD de CVE-2026-123007 (T12)
        changes = [c["change"] for c in self.nvd_history if ts(c["change"]["created"]) <= now]
        if not changes:
            return None
        refs: dict[str, dict[str, Any]] = {}
        for ch in changes:
            for d in ch.get("details", []):
                if d.get("action") != "Added":
                    continue
                if d.get("type") == "Reference":
                    url = d["newValue"]
                    refs.setdefault(url, {"url": url, "tags": [], "tagged_at": None})
                elif d.get("type") == "Reference Type":
                    head, _, types = d["newValue"].rpartition(" Types: ")
                    url = head.partition(": ")[2]
                    ref = refs.setdefault(url, {"url": url, "tags": [], "tagged_at": None})
                    ref["tags"] = [t.strip() for t in types.split(",") if t.strip()]
                    ref["tagged_at"] = ch["created"]
        return {
            "id": cve,
            "published": changes[0]["created"],
            "references": sorted(refs.values(), key=lambda r: r["url"]),
        }


class SimTransport:
    """Transporte simulado: responde lo que cada fuente tenía publicado a `now`."""

    def __init__(self, snaps: Snapshots) -> None:
        self.snaps = snaps
        self.now = START
        self.calls: list[str] = []

    @staticmethod
    def _json(obj: Any, now: datetime | None = None) -> Response:
        headers = {"Date": format_datetime(now, usegmt=True)} if now else {}
        return Response(200, json.dumps(obj).encode(), headers)

    def get(self, url: str, *, headers=None, timeout: float = 0.0) -> Response:
        self.calls.append(url)
        now = self.now
        if url == DEFAULT_DELTA_LOG_URL:
            return self._json(self.snaps.delta_log_at(now))
        if url == KEV_URL:
            return self._json(self.snaps.kev)
        for cve in CVES:
            if url.endswith(f"/{cve}.json") and "cvelistV5" in url:
                rec = self.snaps.record_at(cve, now)
                return self._json(rec) if rec else Response(404, b"not found", {})
        parts = urlsplit(url)
        query = parse_qs(parts.query)
        if url.startswith(NVD_API + "?"):
            cve = query["cveId"][0]
            view = self.snaps.nvd_at(cve, now)
            return self._json(
                {"totalResults": 1 if view else 0, "vulnerabilities": [view] if view else []}
            )
        if url.startswith(SEARCH_API + "?"):
            # Cuándo pasó el repositorio a público es UNKNOWN (PLAN §6): nunca visible.
            return self._json({"total_count": 0, "incomplete_results": False, "items": []}, now)
        return Response(404, b"not found", {})


# -- NVD: no hay conector en el código; se emula con el contrato de `vs.rules.exploit` -----------


class NvdReconstructionConnector(Connector):
    """Emulación de NVD para la reconstrucción. No se registra en `REGISTRY`.

    Por cada referencia con la etiqueta «Exploit» emite la señal `exploit` con `origin =
    reference`, `by = nvd` y sus etiquetas (E4 por referencia, §5.3).
    """

    name = "nvd"
    license_class = LicenseClass.OPEN
    freshness_threshold = timedelta(hours=1)

    def __init__(self, cves: Iterable[str], *, transport, clock) -> None:
        super().__init__({}, transport=transport)
        self.cves = tuple(cves)
        self._clock = clock

    def fetch(self) -> Iterator[dict[str, Any]]:
        self.data_as_of = self._clock()  # API en vivo: el dato es de esta ejecución
        for cve in self.cves:
            data = get_json(self.transport, f"{NVD_API}?cveId={cve}")
            yield from data["vulnerabilities"]

    def normalize(self, raw: Mapping[str, Any]) -> Iterable[Record]:
        for ref in raw["references"]:
            if "exploit" not in {t.casefold() for t in ref["tags"]}:
                continue
            yield Record(
                source=self.name,
                cve_id=raw["id"],
                kind="exploit",
                license_class=self.license_class,
                value={"origin": "reference", "by": "nvd", "tags": list(ref["tags"])},
                source_published_at=ts(ref["tagged_at"]),
                url=ref["url"],
            )


# -- simulación ---------------------------------------------------------------------------------


@dataclass
class Tick:
    at: datetime
    runs: dict[str, str] = field(default_factory=dict)  # fuente → estado
    new: dict[str, list[str]] = field(default_factory=dict)  # CVE → señales nuevas
    levels: dict[str, Level] = field(default_factory=dict)
    why: dict[str, str] = field(default_factory=dict)
    candidates: tuple[str, ...] = ()


@dataclass
class Simulation:
    ticks: list[Tick]
    history: dict[str, list[tuple[datetime, Level, tuple[str, ...]]]]
    publisher: FeedPublisher
    engine: Any


def describe(rec: Record) -> str | None:
    v = rec.value
    if rec.entity is Entity.VULNERABILITY:
        cvss = (v.get("cvss_vector") or "").split("/")[0]
        cwes = ", ".join(v.get("cwe") or [])
        return f"cvelistV5: registro del CNA {v.get('cna')} ({cwes}, {cvss})"
    if rec.entity is Entity.AFFECTED_PRODUCT:
        return f"cvelistV5: producto {v.get('vendor')} / {v.get('product')}"
    if rec.kind == "ssvc":
        return (
            f"cvelistV5: SSVC de {v.get('provider')} (exploitation {v.get('exploitation')}, "
            f"technical_impact {v.get('technical_impact')})"
        )
    if rec.kind == "exploit" and v.get("origin") == "reference":
        return f"NVD: referencia {rec.url} con etiquetas {', '.join(v.get('tags') or [])}"
    if rec.kind == "exploit":
        return f"{rec.source}: repositorio {v.get('repo')}"
    return f"{rec.source}: {rec.kind}"


def why(cve: str, records: Iterable[Record], lists: RuleLists, level: Level) -> str:
    records = list(records)
    if not records:
        return "aún no publicada en ninguna fuente"
    a = assess(cve, records, lists)
    vuln = next((r for r in reversed(records) if r.entity is Entity.VULNERABILITY), None)
    cvss = vuln.value.get("cvss_vector") if vuln else None
    parts = []
    if a.reason:
        parts.append(" + ".join(a.reason))
    if not a.exposed:
        pairs = sorted(
            {
                f"{r.value.get('vendor')} / {r.value.get('product')}"
                for r in records
                if r.entity is Entity.AFFECTED_PRODUCT
            }
        )
        parts.append(f"producto_expuesto: no casa ({'; '.join(pairs)})")
    parts.append(f"impact_class {a.impact_class.value}")
    parts.append(f"rce_sin_auth {'sí' if rce_sin_auth(a.impact_class, cvss) else 'no'}")
    parts.append(f"exploit {a.exploit_rule.value if a.exploit_rule else 'ninguno'}")
    if a.level != level:
        parts.append(f"(reglas: {a.level.label}; publicado: {level.label})")
    return "; ".join(parts)


@cache
def simulate(counterfactual: bool = False) -> Simulation:
    lists = counterfactual_lists() if counterfactual else CONFIG_LISTS
    snaps = Snapshots()
    transport = SimTransport(snaps)
    engine = engine_for_feed(PUBLIC, lists, RulesConfig())
    config = load_feed_config(ROOT / "config" / "brand.example.yaml")
    publisher = FeedPublisher(PUBLIC, config, LocalDevSigner.generate(config.key_id), lists)
    clock_box = {"now": START}

    def clock() -> datetime:
        return clock_box["now"]

    seconds = {"s": 0.0}
    search = GithubSearchConnector(
        {},
        transport=transport,
        limiter=RateLimiter(10, clock=lambda: seconds["s"], sleep=lambda w: None),
        clock=clock,
    )
    connectors: dict[str, Connector] = {
        "cvelistv5": CveListV5Connector({}, transport=transport),
        "cisa_kev": CisaKevConnector({}, transport=transport),
        "nvd": NvdReconstructionConnector([CVE_A], transport=transport, clock=clock),
        "github_search": search,
    }
    cursors: dict[str, datetime | None] = dict.fromkeys(connectors)
    baselines: dict[str, datetime | None] = dict.fromkeys(connectors)
    last_run: dict[str, datetime] = {}
    ticks: list[Tick] = []
    history: dict[str, list[tuple[datetime, Level, tuple[str, ...]]]] = {c: [] for c in CVES}

    now = START
    while now <= STOP:
        clock_box["now"] = now
        transport.now = now
        seconds["s"] = (now - START).total_seconds()
        tick = Tick(now)
        before = {c: len(engine.records(c)) for c in CVES}
        tick.candidates = tuple(c for c in CVES if engine.level(c) in (Level.B, Level.C))
        search.set_candidates(tick.candidates)
        for name, conn in connectors.items():
            if name == "cisa_kev" and name in last_run and now - last_run[name] < KEV_EVERY:
                continue
            last_run[name] = now
            res = run_source(
                conn, since=cursors[name], baseline_completed_at=baselines[name], clock=clock
            )
            tick.runs[name] = res.status.value + (" (carga inicial)" if res.baseline else "")
            if res.status is not RunStatus.OK:
                continue
            cursors[name] = res.data_as_of
            result = engine.ingest(res.records, now)
            if res.baseline_completed:
                engine.complete_baseline(name, res.finished_at)
                baselines[name] = res.finished_at
            for change in result.changes:
                if change.cve_id in history:
                    history[change.cve_id].append((now, change.level_to, change.reason))
        publisher.publish_from_engine(engine, now)
        for c in CVES:
            new = engine.records(c)[before[c] :]
            tick.new[c] = [d for d in dict.fromkeys(describe(r) for r in new) if d]
            tick.levels[c] = engine.level(c)
            tick.why[c] = why(c, engine.records(c), lists, engine.level(c))
        ticks.append(tick)
        now += STEP
    return Simulation(ticks, history, publisher, engine)


# -- traza ---------------------------------------------------------------------------------------


def _row(group: list[Tick]) -> str:
    t = group[0]
    when = hhmm(t.at) if len(group) == 1 else f"{hhmm(t.at)}–{hhmm(group[-1].at)}"
    runs: dict[str, set[str]] = {}
    for g in group:
        for name, status in g.runs.items():
            runs.setdefault(name, set()).add(status)
    runs_text = ", ".join(f"{k} {'/'.join(sorted(v))}" for k, v in runs.items())
    seen = "<br>".join(f"{c[-6:]}: {s}" for c in CVES for s in t.new.get(c, [])) or "—"
    levels = " / ".join(t.levels[c].label for c in CVES)
    why_text = "<br>".join(f"{c[-6:]}: {t.why[c]}" for c in CVES)
    return f"| {when} | {runs_text} | {seen} | {levels} | {why_text} |"


def _same(a: Tick, b: Tick) -> bool:
    return (
        not b.new[CVE_A]
        and not b.new[CVE_B]
        and a.levels == b.levels
        and a.why == b.why
        and a.candidates == b.candidates
    )


def _table(sim: Simulation) -> list[str]:
    lines = [
        "| Hora (UTC) | Fuentes ejecutadas | Señales nuevas | 123007 / 123633 | Por qué |",
        "|---|---|---|---|---|",
    ]
    i = 0
    ticks = sim.ticks
    while i < len(ticks):
        j = i
        while j + 1 < len(ticks) and _same(ticks[i], ticks[j + 1]):
            j += 1
        # El primer paso del grupo trae las señales; los siguientes, sin novedades, se agrupan.
        lines.append(_row([ticks[i]]))
        if j > i:
            lines.append(_row(ticks[i + 1 : j + 1]))
        i = j + 1
    return lines


def _changes(sim: Simulation) -> list[str]:
    out = []
    for c in CVES:
        if not sim.history[c]:
            out.append(f"- {c}: ningún cambio de nivel entre las 15:00Z y las 18:00Z.")
        for at, level, reason in sim.history[c]:
            out.append(f"- {c}: **{level.label}** a las {hhmm(at)}Z ({', '.join(reason)}).")
    return out


def _search_line(sim: Simulation) -> str:
    with_candidates = [t for t in sim.ticks if t.candidates]
    if not with_candidates:
        return "Búsqueda de GitHub: sin candidatos B/C, no se ejecuta ninguna búsqueda."
    return (
        f"Búsqueda de GitHub: candidatos desde las {hhmm(with_candidates[0].at)}Z "
        f"({len(with_candidates)} pasos); el repositorio no aparece porque cuándo pasó a público "
        "es UNKNOWN y se trata como no visible."
    )


def render_trace() -> str:
    real = simulate(False)
    cf = simulate(True)
    rec = real.publisher.record(f"VS-{CVE_A}")
    vs = rec["database_specific"]["vuln_sentinel"]
    lines = [
        BEGIN,
        "<!-- Generado por tests/test_nginx2root_reconstruction.py. No editar a mano. -->",
        "",
        "### Resultado con las listas de `config/`",
        "",
        *_changes(real),
        "",
        *_table(real),
        "",
        f"Registro del feed `VS-{CVE_A}` al final: nivel `{vs['level']}`, "
        f"`impact_class` `{vs['impact_class']}`, "
        f"fix {', '.join(vs['signals']['fix']['versions'])}; "
        f"en el feed `alerts`: {len(real.publisher.logs['alerts'])} entradas.",
        "",
        "### Contrafactual de diagnóstico (no es el resultado)",
        "",
        "Las mismas fuentes con las listas de `config/` más un producto con los pares del CNA",
        "(`F5 / NGINX Open Source`, alias `F5 / NGINX Plus`). No cambia ninguna lista del repo.",
        "",
        *_changes(cf),
        "",
        _search_line(cf),
        END,
    ]
    return "\n".join(lines) + "\n"


# -- pruebas -------------------------------------------------------------------------------------


def test_snapshots_are_what_the_chronology_says():
    """Los datos publicados que usa la reconstrucción (PLAN §6, contrastado el 2026-11-26)."""
    snaps = Snapshots()
    v1 = snaps.versions[CVE_A][0][1]["cveMetadata"]
    assert v1["datePublished"] == "2026-11-18T15:23:29.008Z"
    assert snaps.versions[CVE_B][0][1]["cveMetadata"]["datePublished"] == "2026-11-18T15:23:27.197Z"
    assert snaps.repo["created_at"] == "2026-11-18T11:16:51Z"
    assert snaps.repo["pushed_at"] == "2026-11-18T15:23:27Z"
    assert snaps.repo["owner"]["login"] == "sfewer-r7"
    # KEV del día: ninguna de las dos.
    assert not {v["cveID"] for v in snaps.kev["vulnerabilities"]} & set(CVES)
    # NVD: llega a las 16:18:04 solo con la referencia de F5.
    first = snaps.nvd_at(CVE_A, ts("2026-11-18T16:18:04.047Z"))
    assert first["published"] == "2026-11-18T16:18:04.047"
    assert [r["url"] for r in first["references"]] == [
        "https://my.f5.com/manage/s/article/K000163926"
    ]
    assert snaps.nvd_at(CVE_A, ts("2026-11-18T16:18:00Z")) is None


def test_nvd_exploit_tag_arrives_on_19_11():
    """La etiqueta «Exploit» de NVD llega en el análisis inicial del 19/11 a las 21:14Z."""
    snaps = Snapshots()
    rapid7 = "https://www.rapid7.com/blog/post/ve-cve-2026-123007"

    def tags_at(when: str) -> list[str] | None:
        view = snaps.nvd_at(CVE_A, ts(when))
        refs = [r for r in view["references"] if r["url"].startswith(rapid7)]
        return refs[0]["tags"] if refs else None

    assert tags_at("2026-11-18T18:00:00Z") is None  # la referencia aún no está
    assert tags_at("2026-11-18T20:18:54.867Z") == []  # llega sin etiquetas (CVE Program)
    assert tags_at("2026-11-19T21:14:10.152Z") == []
    assert "Exploit" in tags_at("2026-11-19T21:14:10.153Z")


def test_nvd_reconstruction_matches_current_record():
    """El historial reconstruye las referencias y etiquetas del registro actual de NVD."""
    snaps = Snapshots()
    end = snaps.nvd_at(CVE_A, datetime(2026, 11, 26, tzinfo=UTC))
    current = load("nvd", "CVE-2026-123007.json")["vulnerabilities"][0]["cve"]
    rebuilt = {(r["url"], tuple(sorted(r["tags"]))) for r in end["references"]}
    actual = {(r["url"], tuple(sorted(r.get("tags") or []))) for r in current["references"]}
    assert rebuilt == actual


def test_nomisec_lists_the_poc_after_the_window():
    """PoC-in-GitHub lista el repositorio de Rapid7 por primera vez a las 20:08Z, fuera de la
    ventana."""
    first = load("nomisec", "first-listing.json")
    assert first["entry"]["full_name"] == "sfewer-r7/CVE-2026-123007"
    assert ts(first["committed_at"]) > STOP
    # Si se hubiera visto, el autor está en la lista de confianza (E4 por cuenta).
    assert CONFIG_LISTS.trusted_account(first["entry"]["owner"]["login"])


def test_pipeline_runs_fail_closed_and_without_unknown():
    sim = simulate(False)
    assert len(sim.ticks) == 37
    first = sim.ticks[0]
    assert all("carga inicial" in s for s in first.runs.values())
    for t in sim.ticks:
        assert all(s.startswith("ok") for s in t.runs.values()), (t.at, t.runs)
    # La CVE entra por cvelistV5 en el primer paso tras el commit de las 15:25:28Z.
    seen = next(t for t in sim.ticks if t.new[CVE_A])
    assert seen.at == datetime(2026, 11, 18, 15, 30, tzinfo=UTC)


def test_diagnosis_with_config_lists():
    """Por qué no sale C ni B: el producto no casa; el impacto y la red sí (fija el diagnóstico)."""
    sim = simulate(False)
    for c in CVES:
        a = assess(c, sim.engine.records(c), CONFIG_LISTS)
        assert not a.exposed
        assert a.impact_class.value == "rce"
        assert a.level is Level.NONE
        pairs = {
            (r.value["vendor"], r.value["product"])
            for r in sim.engine.records(c)
            if r.entity is Entity.AFFECTED_PRODUCT
        }
        assert pairs == {("F5", "NGINX Open Source"), ("F5", "NGINX Plus")}
    # La lista solo nombra nginx en `deployment_leg`, que `parse_lists` no carga.
    assert not any("nginx" in p.id for p in CONFIG_LISTS.exposed)
    assert len(sim.publisher.logs["alerts"]) == 0


def test_counterfactual_gives_c_but_no_b_in_window():
    """Diagnóstico: aunque la lista casara, en la ventana sale C y no B (falta la señal de NVD)."""
    sim = simulate(True)
    for c in CVES:
        assert [(hhmm(at), lvl) for at, lvl, _ in sim.history[c]] == [("15:30", Level.C)]


def test_feed_record_has_ranges_and_signature_verifies():
    sim = simulate(False)
    pub = sim.publisher
    for c in CVES:
        rec = pub.record(f"VS-{c}")
        oss = [
            a
            for a in rec["affected"]
            if a["database_specific"].get("product") == "NGINX Open Source"
        ]
        assert oss, rec["affected"]
        fixed = {e["fixed"] for r in oss[0]["ranges"] for e in r["events"] if "fixed" in e}
        assert {"1.30.7", "1.31.9"} <= fixed
        assert {"1.30.7", "1.31.9"} <= set(
            rec["database_specific"]["vuln_sentinel"]["signals"]["fix"]["versions"]
        )
        doc = pub.vuln(f"VS-{c}")
        jws = pub.signature(doc).body.decode("ascii")
        keys = json.loads(pub.keys().body)
        assert verify_detached(jws, doc.body, keys) == pub.signer.kid


def test_trace_is_current():
    """La traza de la bitácora es la que genera esta prueba."""
    block = render_trace()
    text = TRACE_DOC.read_text(encoding="utf-8")
    head, sep1, rest = text.partition(BEGIN)
    _, sep2, tail = rest.partition(END)
    assert sep1 and sep2, f"faltan los marcadores de la traza en {TRACE_DOC}"
    current = BEGIN + rest.partition(END)[0] + END + "\n"
    if os.environ.get("VS_WRITE_TRACE") == "1" and current != block:
        TRACE_DOC.write_text(head + block + "\n" + tail.lstrip("\n"), encoding="utf-8")
        return
    assert current == block, "traza desactualizada: VS_WRITE_TRACE=1 uv run pytest " + __file__


XFAIL_REASON = (
    "nginx2root no pasa en la reconstrucción (T12). (1) producto_expuesto no casa: el CNA firma "
    "F5 / 'NGINX Open Source' y F5 / 'NGINX Plus'; config/exposed-products.yaml solo nombra nginx "
    "en deployment_leg (sin vendor/product/CPE) y parse_lists no carga esa sección. (2) La "
    "etiqueta 'Exploit' de NVD no existía el 18/11: la referencia de Rapid7 llega a NVD a las "
    "20:18Z sin etiquetas y la etiqueta, el 19/11 a las 21:14Z. Preguntas para Juan en "
    "docs/journey/nginx2root-reconstruccion.md."
)


@pytest.mark.xfail(strict=True, reason=XFAIL_REASON)
def test_acceptance_c_after_publication():
    sim = simulate(False)
    for c in CVES:
        first = sim.history[c][0] if sim.history[c] else None
        assert first is not None and first[1] >= Level.C
        assert first[0] <= datetime(2026, 11, 18, 15, 30, tzinfo=UTC)


@pytest.mark.xfail(strict=True, reason=XFAIL_REASON)
def test_acceptance_b_by_nvd_1618():
    sim = simulate(False)
    deadline = datetime(2026, 11, 18, 16, 20, tzinfo=UTC)  # primer paso tras las 16:18Z
    assert any(at <= deadline and lvl >= Level.B for at, lvl, _ in sim.history[CVE_A])
