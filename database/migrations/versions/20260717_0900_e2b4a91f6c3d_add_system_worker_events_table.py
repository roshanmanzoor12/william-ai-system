"""add system_worker_events table

Revision ID: e2b4a91f6c3d
Revises: c1a9f3e2b7d4
Create Date: 2026-07-17 09:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e2b4a91f6c3d'
down_revision: Union[str, None] = 'c1a9f3e2b7d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('system_worker_events',
    sa.Column('event_id', sa.String(length=80), nullable=False),
    sa.Column('user_id', sa.String(length=140), nullable=False),
    sa.Column('workspace_id', sa.String(length=140), nullable=False),
    sa.Column('device_id', sa.String(length=140), nullable=True),
    sa.Column('event_type', sa.String(length=80), nullable=False),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('level', sa.String(length=20), nullable=False),
    sa.Column('worker_task_id', sa.String(length=80), nullable=True),
    sa.Column('action_type', sa.String(length=60), nullable=True),
    sa.Column('metadata_json', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('event_id')
    )
    with op.batch_alter_table('system_worker_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_system_worker_events_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_system_worker_events_workspace_id'), ['workspace_id'], unique=False)
        batch_op.create_index('ix_system_worker_events_workspace_created', ['workspace_id', 'created_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('system_worker_events', schema=None) as batch_op:
        batch_op.drop_index('ix_system_worker_events_workspace_created')
        batch_op.drop_index(batch_op.f('ix_system_worker_events_workspace_id'))
        batch_op.drop_index(batch_op.f('ix_system_worker_events_user_id'))

    op.drop_table('system_worker_events')
