"""Persist tool execution results and normalized workspace findings."""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("results", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
    op.create_index("ix_scan_jobs_state_created", "scan_jobs", ["state", "created_at"], unique=False)
    op.create_table(
        "workspace_scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_user_id", sa.String(length=36), nullable=False),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("profile", sa.String(length=20), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("results", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("progress >= 0 AND progress <= 100", name="ck_workspace_scans_progress"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_workspace_scans_owner_user_id", "workspace_scans", ["owner_user_id"], unique=False)
    op.create_index("ix_workspace_scans_state_created", "workspace_scans", ["state", "created_at"], unique=False)
    with op.batch_alter_table("findings") as batch_op:
        batch_op.alter_column("audit_id", existing_type=sa.String(length=36), nullable=True)
        batch_op.add_column(sa.Column("workspace_scan_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key("fk_findings_workspace_scan_id_workspace_scans", "workspace_scans", ["workspace_scan_id"], ["id"], ondelete="CASCADE")
        batch_op.create_index("ix_findings_workspace_scan_id", ["workspace_scan_id"], unique=False)

def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_index("ix_findings_workspace_scan_id")
        batch_op.drop_constraint("fk_findings_workspace_scan_id_workspace_scans", type_="foreignkey")
        batch_op.drop_column("workspace_scan_id")
        batch_op.alter_column("audit_id", existing_type=sa.String(length=36), nullable=False)
    op.drop_index("ix_workspace_scans_state_created", table_name="workspace_scans")
    op.drop_index("ix_workspace_scans_owner_user_id", table_name="workspace_scans")
    op.drop_table("workspace_scans")
    op.drop_index("ix_scan_jobs_state_created", table_name="scan_jobs")
    op.drop_column("scan_jobs", "results")
