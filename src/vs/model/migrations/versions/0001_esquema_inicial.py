"""Esquema inicial (PLAN.md §8, ADR-0021, ADR-0022).

Generada con autogenerate contra `vs.model.schema` y revisada a mano: los tipos ENUM se crean y se
borran de forma explícita (autogenerate no los borra en `downgrade`).

Revision ID: 0001
Revises:
Create Date: 2026-11-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TZ = postgresql.TIMESTAMP(timezone=True)

alert_level = postgresql.ENUM("none", "C", "B", "A", name="alert_level", create_type=False)
impact_class = postgresql.ENUM(
    "rce", "auth_bypass", "arbitrary_rw", "other", name="impact_class", create_type=False
)
run_status = postgresql.ENUM("ok", "partial", "unknown", name="run_status", create_type=False)
license_class = postgresql.ENUM("open", "restricted", name="license_class", create_type=False)
ENUMS = (alert_level, impact_class, run_status, license_class)

LICENSE_CHECK = (
    "(license_class = 'open' AND licensee IS NULL)"
    " OR (license_class = 'restricted' AND licensee IS NOT NULL)"
)


def _license(table: str) -> list:
    """ADR-0022: las dos columnas de licencia y su CHECK."""
    return [
        sa.Column("license_class", license_class, nullable=False),
        sa.Column("licensee", sa.Text(), nullable=True),
        sa.CheckConstraint(LICENSE_CHECK, name=f"{table}_license_ck"),
    ]


def upgrade() -> None:
    bind = op.get_bind()
    for enum in ENUMS:
        enum.create(bind, checkfirst=False)

    op.create_table(
        "cost_daily",
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("service", sa.Text(), server_default=sa.text("''"), nullable=False),
        sa.Column("amount_eur", sa.Numeric(precision=12, scale=4), nullable=False),
        sa.Column("source_published_at", TZ, nullable=True),
        sa.Column("observed_at", TZ, nullable=False),
        sa.CheckConstraint(
            "provider IN ('azure', 'cloudflare', 'other')", name="cost_daily_provider_ck"
        ),
        sa.PrimaryKeyConstraint("day", "provider", "service", name=op.f("cost_daily_pkey")),
    )
    op.create_table(
        "donation_received",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("channel", sa.Text(), nullable=False),
        sa.Column("amount_sats", sa.BigInteger(), nullable=False),
        sa.Column("received_at", TZ, nullable=False),
        sa.Column("observed_at", TZ, nullable=False),
        sa.Column("external_ref", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "channel IN ('lightning', 'onchain')", name="donation_received_channel_ck"
        ),
        sa.CheckConstraint("amount_sats > 0", name="donation_received_amount_sats_ck"),
        sa.PrimaryKeyConstraint("id", name=op.f("donation_received_pkey")),
        sa.UniqueConstraint("external_ref", name=op.f("donation_received_external_ref_key")),
    )
    op.create_table(
        "metric_daily",
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("metric", sa.Text(), nullable=False),
        sa.Column("dimension", sa.Text(), server_default=sa.text("''"), nullable=False),
        sa.Column("value", sa.Double(), nullable=False),
        sa.PrimaryKeyConstraint("day", "metric", "dimension", name=op.f("metric_daily_pkey")),
    )
    op.create_table(
        "source",
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("baseline_completed_at", TZ, nullable=True),
        sa.Column("freshness_threshold", sa.Interval(), nullable=False),
        *_license("source"),
        sa.PrimaryKeyConstraint("name", name=op.f("source_pkey")),
    )
    op.create_table(
        "source_run",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("started_at", TZ, nullable=False),
        sa.Column("finished_at", TZ, nullable=True),
        sa.Column("status", run_status, nullable=False),
        sa.Column("items_seen", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("items_new", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("last_item_published_at", TZ, nullable=True),
        sa.ForeignKeyConstraint(["source"], ["source.name"], name=op.f("source_run_source_fkey")),
        sa.PrimaryKeyConstraint("id", name=op.f("source_run_pkey")),
    )
    op.create_table(
        "vulnerability",
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("cna", sa.Text(), nullable=True),
        sa.Column("cvss_vector", sa.Text(), nullable=True),
        sa.Column("cvss_source", sa.Text(), nullable=True),
        sa.Column(
            "cwe", postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False
        ),
        sa.Column("impact_class", impact_class, server_default=sa.text("'other'"), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=True),
        sa.Column("product", sa.Text(), nullable=True),
        sa.Column("source_published_at", TZ, nullable=False),
        sa.Column("observed_at", TZ, nullable=False),
        sa.Column("withdrawn_at", TZ, nullable=True),
        sa.Column("baseline", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        *_license("vulnerability"),
        sa.ForeignKeyConstraint(
            ["source"], ["source.name"], name=op.f("vulnerability_source_fkey")
        ),
        sa.PrimaryKeyConstraint("cve_id", name=op.f("vulnerability_pkey")),
    )
    op.create_table(
        "affected_product",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("vendor", sa.Text(), nullable=True),
        sa.Column("product", sa.Text(), nullable=True),
        sa.Column("cpe", sa.Text(), nullable=True),
        sa.Column("purl", sa.Text(), nullable=True),
        sa.Column("ecosystem", sa.Text(), nullable=True),
        sa.Column(
            "ranges",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'"),
            nullable=False,
        ),
        sa.Column("range_source", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=True),
        sa.Column("source_published_at", TZ, nullable=False),
        sa.Column("observed_at", TZ, nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        *_license("affected_product"),
        sa.ForeignKeyConstraint(
            ["cve_id"], ["vulnerability.cve_id"], name=op.f("affected_product_cve_id_fkey")
        ),
        sa.ForeignKeyConstraint(
            ["source"], ["source.name"], name=op.f("affected_product_source_fkey")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("affected_product_pkey")),
    )
    op.create_table(
        "alert",
        sa.Column("alert_id", sa.Text(), nullable=False),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("level", alert_level, nullable=False),
        sa.Column("reason", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("first_published_at", TZ, nullable=False),
        sa.Column("modified_at", TZ, nullable=False),
        sa.ForeignKeyConstraint(
            ["cve_id"], ["vulnerability.cve_id"], name=op.f("alert_cve_id_fkey")
        ),
        sa.PrimaryKeyConstraint("alert_id", name=op.f("alert_pkey")),
        sa.UniqueConstraint("cve_id", name=op.f("alert_cve_id_key")),
    )
    op.create_table(
        "signal",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("baseline", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("source_published_at", TZ, nullable=True),
        sa.Column("observed_at", TZ, nullable=False),
        *_license("signal"),
        sa.ForeignKeyConstraint(
            ["cve_id"], ["vulnerability.cve_id"], name=op.f("signal_cve_id_fkey")
        ),
        sa.ForeignKeyConstraint(["source"], ["source.name"], name=op.f("signal_source_fkey")),
        sa.PrimaryKeyConstraint("id", name=op.f("signal_pkey")),
    )
    op.create_table(
        "ai_call",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.Text(), nullable=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("model", sa.Text(), nullable=False),
        sa.Column("proposed_level", alert_level, nullable=True),
        sa.Column("final_level", alert_level, nullable=True),
        sa.Column("tokens_in", sa.Integer(), nullable=False),
        sa.Column("tokens_out", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Numeric(precision=10, scale=6), nullable=False),
        sa.Column("trace_id", sa.Text(), nullable=True),
        sa.Column("dossier", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "blocked_downgrade", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("at", TZ, nullable=False),
        *_license("ai_call"),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alert.alert_id"], name=op.f("ai_call_alert_id_fkey")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("ai_call_pkey")),
    )
    op.create_table(
        "alert_level_history",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.Text(), nullable=False),
        sa.Column("level_from", alert_level, nullable=False),
        sa.Column("level_to", alert_level, nullable=False),
        sa.Column("reason", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("trigger_signal_id", sa.BigInteger(), nullable=True),
        sa.Column("decided_by", sa.Text(), nullable=False),
        sa.Column("at", TZ, nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alert.alert_id"], name=op.f("alert_level_history_alert_id_fkey")
        ),
        sa.ForeignKeyConstraint(
            ["trigger_signal_id"],
            ["signal.id"],
            name=op.f("alert_level_history_trigger_signal_id_fkey"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("alert_level_history_pkey")),
    )
    op.create_table(
        "publication",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.Text(), nullable=True),
        sa.Column("channel", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.Text(), nullable=True),
        sa.Column("approved_at", TZ, nullable=True),
        sa.Column("sent_at", TZ, nullable=True),
        sa.Column("external_ref", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alert.alert_id"], name=op.f("publication_alert_id_fkey")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("publication_pkey")),
    )
    op.create_table(
        "rule_evaluation",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("evaluated_at", TZ, nullable=False),
        sa.Column("trigger_signal_id", sa.BigInteger(), nullable=True),
        sa.Column("eligible", sa.Boolean(), nullable=False),
        sa.Column("exposed", sa.Boolean(), nullable=False),
        sa.Column("impact_class", impact_class, nullable=False),
        sa.Column("exploit_rule", sa.Text(), nullable=True),
        sa.Column("result_level", alert_level, nullable=False),
        sa.Column("rules_version", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["cve_id"], ["vulnerability.cve_id"], name=op.f("rule_evaluation_cve_id_fkey")
        ),
        sa.ForeignKeyConstraint(
            ["trigger_signal_id"],
            ["signal.id"],
            name=op.f("rule_evaluation_trigger_signal_id_fkey"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("rule_evaluation_pkey")),
    )
    op.create_table(
        "verdict",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.Text(), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("at", TZ, nullable=False),
        sa.CheckConstraint("verdict IN ('util', 'ruido')", name="verdict_verdict_ck"),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alert.alert_id"], name=op.f("verdict_alert_id_fkey")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("verdict_pkey")),
    )


def downgrade() -> None:
    for table in (
        "verdict",
        "rule_evaluation",
        "publication",
        "alert_level_history",
        "ai_call",
        "signal",
        "alert",
        "affected_product",
        "vulnerability",
        "source_run",
        "source",
        "metric_daily",
        "donation_received",
        "cost_daily",
    ):
        op.drop_table(table)
    bind = op.get_bind()
    for enum in reversed(ENUMS):
        enum.drop(bind, checkfirst=False)
