"""Ingesta idempotente y feed persistente (T13).

- `source_run.data_as_of`: fecha del dato según la fuente; es el cursor de la siguiente ejecución.
- `fact_seen`: huella de cada hecho ya visto (idempotencia y carga inicial sin alertas).
- `feed_record` y `feed_change`: el feed publicado (bytes exactos firmados e índice de cambios),
  para que la API y el job de publicación compartan el mismo estado.
- `job_state`: marcas de agua de los jobs y estado del feed.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TZ = postgresql.TIMESTAMP(timezone=True)
alert_level = postgresql.ENUM("none", "C", "B", "A", name="alert_level", create_type=False)


def upgrade() -> None:
    op.add_column("source_run", sa.Column("data_as_of", TZ, nullable=True))
    op.create_table(
        "fact_seen",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("fact_key", sa.Text(), nullable=False),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("baseline", sa.Boolean(), nullable=False),
        sa.Column("first_observed_at", TZ, nullable=False),
        sa.Column("stored", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["source"], ["source.name"], name=op.f("fact_seen_source_fkey")),
        sa.ForeignKeyConstraint(["run_id"], ["source_run.id"], name=op.f("fact_seen_run_id_fkey")),
        sa.PrimaryKeyConstraint("source", "fact_key", name=op.f("fact_seen_pkey")),
    )
    op.create_index(op.f("ix_fact_seen_run_id"), "fact_seen", ["run_id"], unique=False)
    op.create_table(
        "feed_record",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("cve_id", sa.Text(), nullable=False),
        sa.Column("level", alert_level, nullable=False),
        sa.Column("modified", TZ, nullable=False),
        sa.Column("sha256", sa.Text(), nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("feed_record_pkey")),
    )
    op.create_table(
        "feed_change",
        sa.Column("feed", sa.Text(), nullable=False),
        sa.Column("modified", TZ, nullable=False),
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("level", alert_level, nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("sha256", sa.Text(), nullable=False),
        sa.CheckConstraint("feed IN ('all', 'alerts')", name="feed_change_feed_ck"),
        sa.PrimaryKeyConstraint("feed", "modified", "id", name=op.f("feed_change_pkey")),
    )
    op.create_table(
        "job_state",
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", TZ, nullable=False),
        sa.PrimaryKeyConstraint("name", name=op.f("job_state_pkey")),
    )


def downgrade() -> None:
    op.drop_table("job_state")
    op.drop_table("feed_change")
    op.drop_table("feed_record")
    op.drop_index(op.f("ix_fact_seen_run_id"), table_name="fact_seen")
    op.drop_table("fact_seen")
    op.drop_column("source_run", "data_as_of")
