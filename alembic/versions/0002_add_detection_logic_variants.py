"""add detection logic variants

Revision ID: 0002_add_detection_logic_variants
Revises: 0001_initial_detection_schema
Create Date: 2026-06-22 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0002_add_detection_logic_variants"
down_revision = "0001_initial_detection_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_logic_variants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("detection_id", sa.Uuid(), nullable=False),
        sa.Column("language", sa.String(length=32), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.ForeignKeyConstraint(["detection_id"], ["detections.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("detection_id", "language", name="uq_detection_logic_variant_language"),
    )


def downgrade() -> None:
    op.drop_table("detection_logic_variants")
