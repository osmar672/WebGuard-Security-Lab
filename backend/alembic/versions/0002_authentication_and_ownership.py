"""Add user accounts, target ownership, and actor-linked audit events."""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    with op.batch_alter_table("targets") as batch_op:
        batch_op.add_column(sa.Column("owner_user_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key("fk_targets_owner_user_id_users", "users", ["owner_user_id"], ["id"], ondelete="SET NULL")
        batch_op.create_index("ix_targets_owner_user_id", ["owner_user_id"], unique=False)
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.add_column(sa.Column("actor_user_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key("fk_audit_events_actor_user_id_users", "users", ["actor_user_id"], ["id"], ondelete="SET NULL")
        batch_op.create_index("ix_audit_events_actor_user_id", ["actor_user_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("audit_events") as batch_op:
        batch_op.drop_index("ix_audit_events_actor_user_id")
        batch_op.drop_constraint("fk_audit_events_actor_user_id_users", type_="foreignkey")
        batch_op.drop_column("actor_user_id")
    with op.batch_alter_table("targets") as batch_op:
        batch_op.drop_index("ix_targets_owner_user_id")
        batch_op.drop_constraint("fk_targets_owner_user_id_users", type_="foreignkey")
        batch_op.drop_column("owner_user_id")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
