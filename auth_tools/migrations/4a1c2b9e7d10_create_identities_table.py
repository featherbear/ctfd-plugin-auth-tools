"""Create auth_tools_identities table

Revision ID: 4a1c2b9e7d10
Revises:
Create Date: 2026-11-11

"""
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

revision = "4a1c2b9e7d10"
down_revision = None
branch_labels = None
depends_on = None


def _cs_string(length):
    binary = mysql.VARCHAR(length, collation="utf8mb4_bin")
    return sa.String(length).with_variant(binary, "mysql").with_variant(binary, "mariadb")


def upgrade(op=None):
    bind = op.get_bind()
    if sa.inspect(bind).has_table("auth_tools_identities"):
        return
    op.create_table(
        "auth_tools_identities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("provider", _cs_string(128), nullable=False),
        sa.Column("subject", _cs_string(255), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provider", "subject", name="uq_auth_tools_provider_subject"
        ),
    )


def downgrade(op=None):
    op.drop_table("auth_tools_identities")
