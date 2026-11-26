"""Modelo de datos (PLAN.md §8) en SQLAlchemy 2.x. Fuente de verdad del esquema.

Sustituye a `docs/metrics/schema-draft.sql` (F0). Las migraciones de Alembic
(`src/vs/model/migrations/`) se escriben contra este modelo y un test comprueba que no divergen.

Reglas que el esquema impone:
- todo hecho lleva `source_published_at` (cuándo dice la fuente) y `observed_at` (cuándo lo vimos);
- toda tabla con datos de fuentes lleva `license_class` y `licensee` con el mismo CHECK
  (ADR-0022): `restricted` exige `licensee` y `open` lo prohíbe;
- `donation_received` no guarda nada que identifique al donante (ADR-0021).
"""

from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Date,
    Double,
    Enum,
    ForeignKey,
    Integer,
    Interval,
    LargeBinary,
    MetaData,
    Numeric,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column

from vs.sources.base import LicenseClass

# Nombres deterministas: la migración y el modelo tienen que coincidir. Los CHECK llevan siempre
# un nombre explícito y no pasan por la convención.
NAMING_CONVENTION = {
    "pk": "%(table_name)s_pkey",
    "fk": "%(table_name)s_%(column_0_name)s_fkey",
    "uq": "%(table_name)s_%(column_0_name)s_key",
    "ix": "ix_%(table_name)s_%(column_0_name)s",
}

TZ = TIMESTAMP(timezone=True)

ALERT_LEVEL = Enum("none", "C", "B", "A", name="alert_level")
IMPACT_CLASS = Enum("rce", "auth_bypass", "arbitrary_rw", "other", name="impact_class")
RUN_STATUS = Enum("ok", "partial", "unknown", name="run_status")
LICENSE_CLASS = Enum(
    LicenseClass,
    name="license_class",
    values_callable=lambda e: [m.value for m in e],
)

LICENSE_CHECK = (
    "(license_class = 'open' AND licensee IS NULL)"
    " OR (license_class = 'restricted' AND licensee IS NOT NULL)"
)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Licensed:
    """ADR-0022: clase de licencia del dato y, si es restringido, quién tiene la licencia."""

    license_class: Mapped[LicenseClass] = mapped_column(LICENSE_CLASS, sort_order=100)
    licensee: Mapped[str | None] = mapped_column(Text, sort_order=101)

    @declared_attr.directive
    def __table_args__(cls) -> tuple:  # noqa: N805 - firma impuesta por SQLAlchemy
        return (CheckConstraint(LICENSE_CHECK, name=f"{cls.__tablename__}_license_ck"),)


class Source(Licensed, Base):
    __tablename__ = "source"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    # NULL = la carga inicial aún no ha terminado.
    baseline_completed_at: Mapped[datetime | None] = mapped_column(TZ)
    freshness_threshold: Mapped[timedelta] = mapped_column(Interval)


class SourceRun(Base):
    """Estado operativo de cada ejecución de un conector. No guarda datos de la fuente."""

    __tablename__ = "source_run"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(Text, ForeignKey("source.name"))
    started_at: Mapped[datetime] = mapped_column(TZ)
    finished_at: Mapped[datetime | None] = mapped_column(TZ)
    status: Mapped[str] = mapped_column(RUN_STATUS)
    items_seen: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    items_new: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    error: Mapped[str | None] = mapped_column(Text)
    last_item_published_at: Mapped[datetime | None] = mapped_column(TZ)
    # Fecha del dato según la fuente (0002). En una ejecución `ok`, es el cursor de la siguiente.
    data_as_of: Mapped[datetime | None] = mapped_column(TZ)


class FactSeen(Base):
    """Hechos ya vistos de cada fuente (0002), por la huella de `Record.key()`.

    Hace la ingesta idempotente y guarda **cuándo** se vio un hecho por primera vez, también si
    su CVE aún no estaba en `vulnerability` (`stored = false`): cuando la CVE llegue, el hecho se
    guarda con su marca de carga inicial original y no alerta como nuevo. No guarda el dato.
    """

    __tablename__ = "fact_seen"

    source: Mapped[str] = mapped_column(Text, ForeignKey("source.name"), primary_key=True)
    fact_key: Mapped[str] = mapped_column(Text, primary_key=True)  # sha256 hex
    cve_id: Mapped[str] = mapped_column(Text)
    # Ejecución que lo guardó (o que lo vio, si aún no se ha guardado).
    run_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("source_run.id"), index=True)
    baseline: Mapped[bool]
    first_observed_at: Mapped[datetime] = mapped_column(TZ)
    stored: Mapped[bool]


class FeedRecord(Base):
    """Último registro OSV publicado de cada CVE (0002): los bytes exactos que se firman."""

    __tablename__ = "feed_record"

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # VS-CVE-…
    cve_id: Mapped[str] = mapped_column(Text)
    level: Mapped[str] = mapped_column(ALERT_LEVEL)
    modified: Mapped[datetime] = mapped_column(TZ)
    sha256: Mapped[str] = mapped_column(Text)
    body: Mapped[bytes] = mapped_column(LargeBinary)


class FeedChange(Base):
    """Índice de cambios de cada feed (0002, ADR-0019). Solo inserción; se poda por retención."""

    __tablename__ = "feed_change"
    __table_args__ = (CheckConstraint("feed IN ('all', 'alerts')", name="feed_change_feed_ck"),)

    feed: Mapped[str] = mapped_column(Text, primary_key=True)
    modified: Mapped[datetime] = mapped_column(TZ, primary_key=True)
    id: Mapped[str] = mapped_column(Text, primary_key=True)
    level: Mapped[str] = mapped_column(ALERT_LEVEL)
    type: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(Text)


class JobState(Base):
    """Estado de cada job entre ejecuciones (0002): marcas de agua y estado del feed."""

    __tablename__ = "job_state"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(TZ)


class Vulnerability(Licensed, Base):
    __tablename__ = "vulnerability"

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    cna: Mapped[str | None] = mapped_column(Text)
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    cvss_source: Mapped[str | None] = mapped_column(Text)
    cwe: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    impact_class: Mapped[str] = mapped_column(IMPACT_CLASS, server_default=text("'other'"))
    vendor: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    source_published_at: Mapped[datetime] = mapped_column(TZ)
    observed_at: Mapped[datetime] = mapped_column(TZ)
    withdrawn_at: Mapped[datetime | None] = mapped_column(TZ)
    baseline: Mapped[bool] = mapped_column(server_default=text("false"))
    source: Mapped[str] = mapped_column(Text, ForeignKey("source.name"))


class AffectedProduct(Licensed, Base):
    __tablename__ = "affected_product"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(Text, ForeignKey("vulnerability.cve_id"))
    vendor: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    cpe: Mapped[str | None] = mapped_column(Text)
    purl: Mapped[str | None] = mapped_column(Text)
    ecosystem: Mapped[str | None] = mapped_column(Text)
    ranges: Mapped[Any] = mapped_column(JSONB, server_default=text("'[]'"))
    # Quién da el rango; `source` es el conector que lo trajo.
    range_source: Mapped[str] = mapped_column(Text)
    # De config/exposed-products.yaml; NULL = no expuesto.
    category: Mapped[str | None] = mapped_column(Text)
    source_published_at: Mapped[datetime] = mapped_column(TZ)
    observed_at: Mapped[datetime] = mapped_column(TZ)
    source: Mapped[str] = mapped_column(Text, ForeignKey("source.name"))


class Signal(Licensed, Base):
    """Solo inserción: el historial de una señal es la propia tabla."""

    __tablename__ = "signal"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(Text, ForeignKey("vulnerability.cve_id"))
    # kev_cisa, kev_vulncheck, ssvc, epss, exploit, fix, mitigation, vendor_exploited
    kind: Mapped[str] = mapped_column(Text)
    value: Mapped[Any] = mapped_column(JSONB)
    source: Mapped[str] = mapped_column(Text, ForeignKey("source.name"))
    url: Mapped[str | None] = mapped_column(Text)
    baseline: Mapped[bool] = mapped_column(server_default=text("false"))
    # NULL si la fuente no da hora (KEV: solo fecha).
    source_published_at: Mapped[datetime | None] = mapped_column(TZ)
    observed_at: Mapped[datetime] = mapped_column(TZ)


class RuleEvaluation(Base):
    """Una fila por evaluación de reglas (R5): permite el embudo."""

    __tablename__ = "rule_evaluation"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(Text, ForeignKey("vulnerability.cve_id"))
    evaluated_at: Mapped[datetime] = mapped_column(TZ)
    trigger_signal_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("signal.id"))
    # §5.1: reciente o señal nueva tras la carga inicial.
    eligible: Mapped[bool]
    exposed: Mapped[bool]
    impact_class: Mapped[str] = mapped_column(IMPACT_CLASS)
    exploit_rule: Mapped[str | None] = mapped_column(Text)  # E1..E5 o NULL
    result_level: Mapped[str] = mapped_column(ALERT_LEVEL)
    rules_version: Mapped[str] = mapped_column(Text)


class Alert(Base):
    __tablename__ = "alert"

    alert_id: Mapped[str] = mapped_column(Text, primary_key=True)  # VS-CVE-…
    cve_id: Mapped[str] = mapped_column(Text, ForeignKey("vulnerability.cve_id"), unique=True)
    level: Mapped[str] = mapped_column(ALERT_LEVEL)
    reason: Mapped[list[str]] = mapped_column(ARRAY(Text))
    status: Mapped[str] = mapped_column(Text)
    first_published_at: Mapped[datetime] = mapped_column(TZ)
    modified_at: Mapped[datetime] = mapped_column(TZ)


class AlertLevelHistory(Base):
    __tablename__ = "alert_level_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(Text, ForeignKey("alert.alert_id"))
    level_from: Mapped[str] = mapped_column(ALERT_LEVEL)
    level_to: Mapped[str] = mapped_column(ALERT_LEVEL)
    reason: Mapped[list[str]] = mapped_column(ARRAY(Text))
    trigger_signal_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("signal.id"))
    decided_by: Mapped[str] = mapped_column(Text)  # rules | ai | juan
    at: Mapped[datetime] = mapped_column(TZ)


class AiCall(Licensed, Base):
    """El dosier cita fuentes: hereda la clase más restrictiva de lo que leyó el agente."""

    __tablename__ = "ai_call"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    alert_id: Mapped[str | None] = mapped_column(Text, ForeignKey("alert.alert_id"))
    kind: Mapped[str] = mapped_column(Text)  # agent | draft
    model: Mapped[str] = mapped_column(Text)
    proposed_level: Mapped[str | None] = mapped_column(ALERT_LEVEL)
    final_level: Mapped[str | None] = mapped_column(ALERT_LEVEL)
    tokens_in: Mapped[int] = mapped_column(Integer)
    tokens_out: Mapped[int] = mapped_column(Integer)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(10, 6))
    trace_id: Mapped[str | None] = mapped_column(Text)
    dossier: Mapped[Any | None] = mapped_column(JSONB)
    blocked_downgrade: Mapped[bool] = mapped_column(server_default=text("false"))
    at: Mapped[datetime] = mapped_column(TZ)


class Publication(Base):
    __tablename__ = "publication"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    alert_id: Mapped[str | None] = mapped_column(Text, ForeignKey("alert.alert_id"))
    channel: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text)
    approved_by: Mapped[str | None] = mapped_column(Text)
    approved_at: Mapped[datetime | None] = mapped_column(TZ)
    sent_at: Mapped[datetime | None] = mapped_column(TZ)
    external_ref: Mapped[str | None] = mapped_column(Text)


class Verdict(Base):
    __tablename__ = "verdict"
    __table_args__ = (CheckConstraint("verdict IN ('util', 'ruido')", name="verdict_verdict_ck"),)

    # El borrador no tenía PK; el ORM la necesita. Un id no cambia lo que guardan las consultas.
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(Text, ForeignKey("alert.alert_id"))
    verdict: Mapped[str] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(TZ)


class CostDaily(Base):
    """Transparencia de costes (§9): Azure Cost Management (RG) y facturación de Cloudflare."""

    __tablename__ = "cost_daily"
    __table_args__ = (
        CheckConstraint(
            "provider IN ('azure', 'cloudflare', 'other')", name="cost_daily_provider_ck"
        ),
    )

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    provider: Mapped[str] = mapped_column(Text, primary_key=True)
    service: Mapped[str] = mapped_column(Text, primary_key=True, server_default=text("''"))
    amount_eur: Mapped[Decimal] = mapped_column(Numeric(12, 4))
    source_published_at: Mapped[datetime | None] = mapped_column(TZ)
    observed_at: Mapped[datetime] = mapped_column(TZ)


class DonationReceived(Base):
    """Donaciones recibidas (ADR-0021). SIN datos del donante: ni nombre, ni IP, ni dirección de
    origen, ni mensaje. Solo importe, fecha y canal. La referencia externa es opaca (id de factura
    o txid)."""

    __tablename__ = "donation_received"
    __table_args__ = (
        CheckConstraint("channel IN ('lightning', 'onchain')", name="donation_received_channel_ck"),
        CheckConstraint("amount_sats > 0", name="donation_received_amount_sats_ck"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    channel: Mapped[str] = mapped_column(Text)
    amount_sats: Mapped[int] = mapped_column(BigInteger)
    received_at: Mapped[datetime] = mapped_column(TZ)
    observed_at: Mapped[datetime] = mapped_column(TZ)
    external_ref: Mapped[str] = mapped_column(Text, unique=True)


class MetricDaily(Base):
    __tablename__ = "metric_daily"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    metric: Mapped[str] = mapped_column(Text, primary_key=True)
    dimension: Mapped[str] = mapped_column(Text, primary_key=True, server_default=text("''"))
    value: Mapped[float] = mapped_column(Double)


metadata = Base.metadata
