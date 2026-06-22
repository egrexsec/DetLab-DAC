"""initial detection schema

Revision ID: 0001_initial_detection_schema
Revises:
Create Date: 2026-06-21 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0001_initial_detection_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "attack_tactics",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("attack_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("short_name", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("attack_id"),
        sa.UniqueConstraint("short_name"),
    )

    op.create_table(
        "detections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("detection_id", sa.String(length=32), nullable=False),
        sa.Column("slug", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("author", sa.String(length=255), nullable=False),
        sa.Column("logsource_product", sa.String(length=255), nullable=False),
        sa.Column("logsource_service", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("detection_id"),
        sa.UniqueConstraint("slug"),
    )

    op.create_table(
        "attack_techniques",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("attack_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("tactic_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["tactic_id"], ["attack_tactics.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("attack_id"),
    )

    op.create_table(
        "detection_references",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("detection_id", sa.Uuid(), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.ForeignKeyConstraint(["detection_id"], ["detections.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("detection_id", "url", name="uq_detection_reference_url"),
    )

    op.create_table(
        "detection_tags",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("detection_id", sa.Uuid(), nullable=False),
        sa.Column("tag", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(["detection_id"], ["detections.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("detection_id", "tag", name="uq_detection_tag"),
    )

    op.create_table(
        "detection_attack_mappings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("detection_id", sa.Uuid(), nullable=False),
        sa.Column("technique_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["detection_id"], ["detections.id"]),
        sa.ForeignKeyConstraint(["technique_id"], ["attack_techniques.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("detection_id", "technique_id", name="uq_detection_technique_mapping"),
    )


def downgrade() -> None:
    op.drop_table("detection_attack_mappings")
    op.drop_table("detection_tags")
    op.drop_table("detection_references")
    op.drop_table("attack_techniques")
    op.drop_table("detections")
    op.drop_table("attack_tactics")