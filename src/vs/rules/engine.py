"""Motor de reglas A/B/C (PLAN.md §5): determinista, por feed y monótono.

- `assess` calcula el nivel de una CVE a partir de sus hechos y señales (§5.2, §5.3).
- `RuleEngine` recibe lotes de registros ya sellados por el ejecutor (`vs.sources.run`), decide
  qué es «nuevo» (§5.1, ADR-0012), deja una `Evaluation` por CVE y lote (`rule_evaluation`) y
  emite un `LevelChange` (`alert_level_history`) cuando el nivel publicado sube.

Derechos (ADR-0022): el motor trabaja para **una audiencia**. Todo registro que esa audiencia no
puede recibir se descarta antes de guardarlo, así que el nivel de cada feed sale solo de las
señales permitidas en él.

Carga inicial (ADR-0012, CTL-007): un lote en el que todos los registros de una CVE son de carga
inicial (`baseline = true`) nunca alerta. Una CVE es elegible si:
  (a) tiene registros que no son de carga inicial y se publicó en los últimos N días; o
  (b) una señal nueva (posterior a la carga inicial de su fuente) sube su nivel.
Una señal que no cambia el nivel (p. ej. el EPSS diario) no hace elegible una CVE antigua.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from vs.rules.exploit import EXPLOIT_KIND, E5Reviewer, ExploitRule, exploit_rules, poc_status
from vs.rules.impact import ImpactClass, impact_class, rce_sin_auth
from vs.rules.levels import RULES_VERSION, Level, final_level
from vs.rules.lists import EMPTY_LISTS, ProductRef, RuleLists, producto_expuesto
from vs.sources.base import Entity, Record

DEFAULT_RECENT_DAYS = 14

# Señales que dan A por sí solas (§5.2 y ADR-0022 §8). `kev_vulncheck` es `restricted`: solo
# cuenta en un feed con su licencia; en el público la filtra la audiencia.
A_KINDS: Mapping[str, str] = {
    "kev_cisa": "A.kev_cisa",
    "kev_vulncheck": "A.kev_vulncheck",
    "vendor_exploited": "A.vendor_exploited",
}
_SSVC_EXPLOITATION = {"none": 0, "poc": 1, "active": 2}


@dataclass(frozen=True)
class RulesConfig:
    recent_days: int = DEFAULT_RECENT_DAYS  # N del §5.1

    @property
    def recent(self) -> timedelta:
        return timedelta(days=self.recent_days)


@dataclass(frozen=True)
class Assessment:
    level: Level
    reason: tuple[str, ...]
    impact_class: ImpactClass
    exposed: bool
    category: str | None
    exploit_rule: ExploitRule | None


def _ssvc(signals: Iterable[Record]) -> tuple[str | None, bool]:
    """(explotación más alta, ¿algún `technical_impact = total`?) de las señales SSVC."""
    best: str | None = None
    total = False
    for s in signals:
        if s.kind != "ssvc":
            continue
        e = str(s.value.get("exploitation") or "").lower()
        if e in _SSVC_EXPLOITATION and (
            best is None or _SSVC_EXPLOITATION[e] > _SSVC_EXPLOITATION[best]
        ):
            best = e
        total = total or str(s.value.get("technical_impact") or "").lower() == "total"
    return best, total


_NEVER = datetime.min.replace(tzinfo=UTC)


def _latest_vuln(records: Iterable[Record]) -> Record | None:
    """El último registro `vulnerability` visto (a igual hora, el último del lote)."""
    latest: Record | None = None
    for r in records:
        if r.entity is not Entity.VULNERABILITY:
            continue
        if latest is None or (r.observed_at or _NEVER) >= (latest.observed_at or _NEVER):
            latest = r
    return latest


def _product_refs(records: Iterable[Record]) -> list[ProductRef]:
    refs = []
    for r in records:
        if r.entity in (Entity.VULNERABILITY, Entity.AFFECTED_PRODUCT):
            v = r.value
            refs.append(ProductRef(v.get("vendor"), v.get("product"), v.get("cpe"), v.get("purl")))
    return refs


def assess(
    cve_id: str,
    records: Iterable[Record],
    lists: RuleLists = EMPTY_LISTS,
    e5: E5Reviewer | None = None,
) -> Assessment:
    """Nivel determinista de una CVE con los registros dados (§5.2). No mira el tiempo."""
    records = [r for r in records if r.cve_id == cve_id]
    signals = [r for r in records if r.entity is Entity.SIGNAL]
    vuln = _latest_vuln(records)
    cwes = vuln.value.get("cwe") if vuln else None
    cvss = vuln.value.get("cvss_vector") if vuln else None

    exploitation, total = _ssvc(signals)
    impact = impact_class(cwes, cvss, "total" if total else None)
    product = producto_expuesto(_product_refs(records), lists)
    exposed = product is not None
    category = product.category if product else None
    exploits = [s.value for s in signals if s.kind == EXPLOIT_KIND]
    rules = exploit_rules(exploits, exploitation, lists)
    rule = rules[0] if rules else None

    def result(level: Level, reason: list[str], r: ExploitRule | None = rule) -> Assessment:
        return Assessment(level, tuple(reason), impact, exposed, category, r)

    a_reason = sorted({A_KINDS[s.kind] for s in signals if s.kind in A_KINDS})
    if exploitation == "active":
        a_reason.append("A.ssvc_exploitation:active")
    if a_reason:
        return result(Level.A, a_reason)

    if not exposed or impact is ImpactClass.OTHER:
        return result(Level.NONE, [])
    base = [f"B.exposed_product:{category}", f"B.impact:{impact.value}"]
    if rule is not None:
        return result(Level.B, [*base, f"B.exploit:{rule.value}"])
    if not rce_sin_auth(impact, cvss):
        return result(Level.NONE, [])
    # C. E5 solo puede llevarla a B (§5.3).
    if e5 is not None:
        for v in exploits:
            if poc_status(v, lists) == "poc_unverified" and e5.confirms(cve_id, v):
                return result(Level.B, [*base, "B.exploit:E5"], ExploitRule.E5)
    c_reason = [f"C.exposed_product:{category}", f"C.impact:{impact.value}", "C.rce_unauth"]
    return result(Level.C, c_reason)


class AudienceLike(Protocol):
    name: str

    def allows(self, rec: Record) -> bool: ...


@dataclass(frozen=True)
class Evaluation:
    """Una fila de `rule_evaluation` (R5): una por CVE y lote evaluado."""

    cve_id: str
    feed: str
    evaluated_at: datetime
    trigger: Record | None
    eligible: bool
    exposed: bool
    category: str | None
    impact_class: ImpactClass
    exploit_rule: ExploitRule | None
    computed_level: Level  # lo que dan las reglas con todo lo visto
    reason: tuple[str, ...]
    rules_version: str = RULES_VERSION

    @property
    def result_level(self) -> Level:
        """Nivel de la evaluación para el embudo: NONE si no era elegible (§9)."""
        return self.computed_level if self.eligible else Level.NONE

    def to_row(self, trigger_signal_id: int | None = None) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "evaluated_at": self.evaluated_at,
            "trigger_signal_id": trigger_signal_id,
            "eligible": self.eligible,
            "exposed": self.exposed,
            "impact_class": self.impact_class.value,
            "exploit_rule": self.exploit_rule.value if self.exploit_rule else None,
            "result_level": self.result_level.label,
            "rules_version": self.rules_version,
        }


@dataclass(frozen=True)
class LevelChange:
    """Fila de `alert_level_history`. `decided_by`: `rules`, `ai` o el nombre de quien la baja."""

    cve_id: str
    feed: str
    level_from: Level
    level_to: Level
    reason: tuple[str, ...]
    decided_by: str
    at: datetime
    trigger: Record | None = None

    @property
    def alert_id(self) -> str:
        return f"VS-{self.cve_id}"

    def to_row(self, trigger_signal_id: int | None = None) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "level_from": self.level_from.label,
            "level_to": self.level_to.label,
            "reason": list(self.reason),
            "trigger_signal_id": trigger_signal_id,
            "decided_by": self.decided_by,
            "at": self.at,
        }


@dataclass
class BatchResult:
    evaluations: list[Evaluation] = field(default_factory=list)
    changes: list[LevelChange] = field(default_factory=list)
    dropped_by_rights: int = 0

    @property
    def alerts(self) -> list[LevelChange]:
        """Cambios que despiertan a alguien: el nivel sube a A, B o C."""
        return [c for c in self.changes if c.level_to > c.level_from]


AUTOMATIC_DECIDERS = frozenset({"rules", "ai"})


class RuleEngine:
    """Estado de las reglas de **un feed**. En memoria; la persistencia la pone quien lo use."""

    def __init__(
        self,
        audience: AudienceLike,
        lists: RuleLists = EMPTY_LISTS,
        config: RulesConfig | None = None,
        baselines: Mapping[str, datetime | None] | None = None,
        e5: E5Reviewer | None = None,
    ) -> None:
        self.audience = audience
        self.lists = lists
        self.config = config or RulesConfig()
        # source -> baseline_completed_at (None = la carga inicial aún no ha terminado)
        self.baselines: dict[str, datetime | None] = dict(baselines or {})
        self.e5 = e5
        self._records: dict[str, list[Record]] = {}
        self._keys: set[tuple[str, str, str, str, str]] = set()
        self._published: dict[str, Level] = {}
        self.history: list[LevelChange] = []

    # -- estado -----------------------------------------------------------------------------

    def complete_baseline(self, source: str, at: datetime) -> None:
        """`source.baseline_completed_at`: tras la primera ejecución `ok` de la fuente."""
        if self.baselines.get(source) is None:
            self.baselines[source] = at

    def restore(
        self,
        cve_id: str,
        records: Iterable[Record],
        level: Level = Level.NONE,
        history: Iterable[LevelChange] = (),
    ) -> None:
        """Carga el estado guardado de una CVE (registros ya evaluados y nivel publicado).

        No evalúa nada: es el estado previo al siguiente `ingest`. Lo usan los jobs, que guardan el
        estado en la base de datos entre ejecuciones (`vs.store`).
        """
        kept = self._records.setdefault(cve_id, [])
        for r in records:
            if r.cve_id != cve_id or not self.audience.allows(r):
                continue
            key = r.key()
            if key in self._keys:
                continue
            self._keys.add(key)
            kept.append(r)
        if level is not Level.NONE:
            self._published[cve_id] = level
        self.history.extend(c for c in history if c.cve_id == cve_id)

    def level(self, cve_id: str) -> Level:
        """Nivel publicado de la CVE en este feed. Solo sube, salvo acto manual."""
        return self._published.get(cve_id, Level.NONE)

    def records(self, cve_id: str) -> tuple[Record, ...]:
        return tuple(self._records.get(cve_id, ()))

    def cve_ids(self) -> list[str]:
        """CVE con algún registro en este feed, ordenadas."""
        return sorted(self._records)

    def _is_new_signal(self, r: Record) -> bool:
        if r.entity is not Entity.SIGNAL or r.baseline:
            return False
        done = self.baselines.get(r.source)
        return done is not None and r.observed_at is not None and r.observed_at > done

    def _set_level(self, change: LevelChange) -> None:
        self._published[change.cve_id] = change.level_to
        self.history.append(change)

    # -- evaluación -------------------------------------------------------------------------

    def ingest(self, records: Iterable[Record], now: datetime) -> BatchResult:
        """Guarda un lote (filtrado por la audiencia y sin repetidos) y evalúa cada CVE tocada."""
        out = BatchResult()
        batch: dict[str, list[Record]] = {}
        for r in records:
            if not self.audience.allows(r):
                out.dropped_by_rights += 1
                continue
            key = r.key()
            if key in self._keys:
                continue
            self._keys.add(key)
            batch.setdefault(r.cve_id, []).append(r)

        for cve_id in sorted(batch):
            new = batch[cve_id]
            before = self._records.setdefault(cve_id, [])
            before.extend(new)
            out_eval, change = self._evaluate(cve_id, before, new, now)
            out.evaluations.append(out_eval)
            if change is not None:
                self._set_level(change)
                out.changes.append(change)
        return out

    def _evaluate(
        self, cve_id: str, all_records: list[Record], new: list[Record], now: datetime
    ) -> tuple[Evaluation, LevelChange | None]:
        after = assess(cve_id, all_records, self.lists, self.e5)
        new_signals = [r for r in new if self._is_new_signal(r)]

        # (b) ¿alguna señal nueva sube el nivel? Se compara con lo que había sin ellas.
        trigger: Record | None = None
        eligible_b = False
        if new_signals:
            fresh = {id(r) for r in new_signals}
            without = [r for r in all_records if id(r) not in fresh]
            base = assess(cve_id, without, self.lists, self.e5)
            if after.level > base.level:
                eligible_b = True
                for s in new_signals:
                    if assess(cve_id, [*without, s], self.lists, self.e5).level > base.level:
                        trigger = s
                        break
                trigger = trigger or new_signals[0]

        # (a) publicada hace menos de N días y el lote no es solo de carga inicial.
        eligible_a = False
        if not all(r.baseline for r in new):
            vuln = _latest_vuln(all_records)
            published = vuln.source_published_at if vuln else None
            eligible_a = published is not None and now - published <= self.config.recent
            if eligible_a and trigger is None:
                trigger = next((r for r in new if r.entity is Entity.SIGNAL), None)

        eligible = eligible_a or eligible_b
        evaluation = Evaluation(
            cve_id=cve_id,
            feed=self.audience.name,
            evaluated_at=now,
            trigger=trigger,
            eligible=eligible,
            exposed=after.exposed,
            category=after.category,
            impact_class=after.impact_class,
            exploit_rule=after.exploit_rule,
            computed_level=after.level,
            reason=after.reason,
        )
        current = self.level(cve_id)
        decided = final_level(after.level, published=current).level
        if not eligible or decided <= current:
            return evaluation, None
        change = LevelChange(
            cve_id=cve_id,
            feed=self.audience.name,
            level_from=current,
            level_to=decided,
            reason=after.reason,
            decided_by="rules",
            at=now,
            trigger=trigger,
        )
        return evaluation, change

    def apply_ai(
        self, cve_id: str, proposed: Level, reason: Iterable[str], now: datetime
    ) -> tuple[LevelChange | None, bool]:
        """Propuesta de la IA: `max(publicado, IA)`. Devuelve el cambio y si bloqueó una bajada."""
        current = self.level(cve_id)
        fl = final_level(current, ai=proposed, published=current)
        if fl.level <= current:
            return None, fl.blocked_downgrade
        change = LevelChange(
            cve_id, self.audience.name, current, fl.level, tuple(reason), "ai", now
        )
        self._set_level(change)
        return change, fl.blocked_downgrade

    def manual_set_level(
        self, cve_id: str, level: Level, decided_by: str, reason: Iterable[str], now: datetime
    ) -> LevelChange:
        """Único camino para bajar un nivel: acto manual con autor y motivo, y queda registrado."""
        who = (decided_by or "").strip()
        why = tuple(r for r in reason if str(r).strip())
        if not who or who in AUTOMATIC_DECIDERS:
            raise ValueError("un cambio manual de nivel exige una persona en 'decided_by'")
        if not why:
            raise ValueError("un cambio manual de nivel exige un motivo")
        change = LevelChange(cve_id, self.audience.name, self.level(cve_id), level, why, who, now)
        self._set_level(change)
        return change
