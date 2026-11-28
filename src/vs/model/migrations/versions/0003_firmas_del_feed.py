"""Firmas del feed hechas por el job de publicación (ADR-0026).

- `feed_signature`: la firma JWS detached de cada documento firmable, con el sha256 de los bytes
  firmados. La API la sirve sin tener la clave. `body` solo en los documentos que la API no puede
  reconstruir igual (`alerts/latest.json`, `keys.json`).

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TZ = postgresql.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "feed_signature",
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("sha256", sa.Text(), nullable=False),
        sa.Column("jws", sa.Text(), nullable=True),
        sa.Column("kid", sa.Text(), nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=True),
        sa.Column("signed_at", TZ, nullable=False),
        sa.Column("expires_at", TZ, nullable=True),
        sa.PrimaryKeyConstraint("path", name=op.f("feed_signature_pkey")),
    )


def downgrade() -> None:
    op.drop_table("feed_signature")
