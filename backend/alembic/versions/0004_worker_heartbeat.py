"""Persist the configured tool worker heartbeat/capabilities."""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        "worker_heartbeats",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

def downgrade() -> None:
    op.drop_table("worker_heartbeats")
