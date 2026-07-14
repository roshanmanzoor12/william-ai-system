"""add worker_tasks table and widen system_worker_status

Revision ID: 8a3eda447ad8
Revises: 2a9a06865ea1
Create Date: 2026-07-14 08:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8a3eda447ad8'
down_revision: Union[str, None] = '2a9a06865ea1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('worker_tasks',
    sa.Column('task_id', sa.String(length=80), nullable=False),
    sa.Column('user_id', sa.String(length=140), nullable=False),
    sa.Column('workspace_id', sa.String(length=140), nullable=False),
    sa.Column('device_id', sa.String(length=140), nullable=True),
    sa.Column('action_type', sa.String(length=60), nullable=False),
    sa.Column('action_payload_json', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('requires_approval', sa.Boolean(), nullable=False),
    sa.Column('approved_by_security', sa.Boolean(), nullable=False),
    sa.Column('result_message', sa.Text(), nullable=True),
    sa.Column('error_code', sa.String(length=120), nullable=True),
    sa.Column('error_details', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('task_id')
    )
    with op.batch_alter_table('worker_tasks', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_worker_tasks_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_worker_tasks_workspace_id'), ['workspace_id'], unique=False)
        batch_op.create_index('ix_worker_tasks_workspace_status', ['workspace_id', 'status'], unique=False)

    with op.batch_alter_table('system_worker_status', schema=None) as batch_op:
        batch_op.add_column(sa.Column('device_name', sa.String(length=140), nullable=True))
        batch_op.add_column(sa.Column('supported_actions_json', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('last_command', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('last_result', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('system_worker_status', schema=None) as batch_op:
        batch_op.drop_column('last_result')
        batch_op.drop_column('last_command')
        batch_op.drop_column('supported_actions_json')
        batch_op.drop_column('device_name')

    with op.batch_alter_table('worker_tasks', schema=None) as batch_op:
        batch_op.drop_index('ix_worker_tasks_workspace_status')
        batch_op.drop_index(batch_op.f('ix_worker_tasks_workspace_id'))
        batch_op.drop_index(batch_op.f('ix_worker_tasks_user_id'))

    op.drop_table('worker_tasks')
