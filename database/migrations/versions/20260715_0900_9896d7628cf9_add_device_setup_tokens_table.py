"""add device_setup_tokens table and widen system_worker_status for device tokens

Revision ID: 9896d7628cf9
Revises: 8a3eda447ad8
Create Date: 2026-07-15 09:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9896d7628cf9'
down_revision: Union[str, None] = '8a3eda447ad8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('device_setup_tokens',
    sa.Column('token_id', sa.String(length=80), nullable=False),
    sa.Column('token_hash', sa.String(length=128), nullable=False),
    sa.Column('user_id', sa.String(length=140), nullable=False),
    sa.Column('workspace_id', sa.String(length=140), nullable=False),
    sa.Column('device_type', sa.String(length=20), nullable=False),
    sa.Column('allowed_actions_json', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('token_id')
    )
    with op.batch_alter_table('device_setup_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_device_setup_tokens_token_hash'), ['token_hash'], unique=True)
        batch_op.create_index(batch_op.f('ix_device_setup_tokens_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_device_setup_tokens_workspace_id'), ['workspace_id'], unique=False)
        batch_op.create_index('ix_device_setup_tokens_workspace_status', ['workspace_id', 'status'], unique=False)

    with op.batch_alter_table('system_worker_status', schema=None) as batch_op:
        batch_op.add_column(sa.Column('owner_user_id', sa.String(length=140), nullable=True))
        batch_op.add_column(sa.Column('device_id', sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column('device_token_hash', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('device_token_status', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('setup_completed_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index(
            batch_op.f('ix_system_worker_status_device_token_hash'), ['device_token_hash'], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table('system_worker_status', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_system_worker_status_device_token_hash'))
        batch_op.drop_column('setup_completed_at')
        batch_op.drop_column('device_token_status')
        batch_op.drop_column('device_token_hash')
        batch_op.drop_column('device_id')
        batch_op.drop_column('owner_user_id')

    with op.batch_alter_table('device_setup_tokens', schema=None) as batch_op:
        batch_op.drop_index('ix_device_setup_tokens_workspace_status')
        batch_op.drop_index(batch_op.f('ix_device_setup_tokens_workspace_id'))
        batch_op.drop_index(batch_op.f('ix_device_setup_tokens_user_id'))
        batch_op.drop_index(batch_op.f('ix_device_setup_tokens_token_hash'))

    op.drop_table('device_setup_tokens')
