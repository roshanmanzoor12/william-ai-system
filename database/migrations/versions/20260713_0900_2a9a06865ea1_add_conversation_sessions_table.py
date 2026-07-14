"""add conversation_sessions table

Revision ID: 2a9a06865ea1
Revises: af60ed6c1906
Create Date: 2026-07-13 09:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2a9a06865ea1'
down_revision: Union[str, None] = 'af60ed6c1906'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('conversation_sessions',
    sa.Column('conversation_thread_id', sa.String(length=80), nullable=False),
    sa.Column('user_id', sa.String(length=140), nullable=False),
    sa.Column('workspace_id', sa.String(length=140), nullable=False),
    sa.Column('pending_task_id', sa.String(length=140), nullable=True),
    sa.Column('parent_task_id', sa.String(length=140), nullable=True),
    sa.Column('intent_category', sa.String(length=60), nullable=False),
    sa.Column('template_key', sa.String(length=60), nullable=True),
    sa.Column('required_inputs_json', sa.Text(), nullable=True),
    sa.Column('collected_inputs_json', sa.Text(), nullable=True),
    sa.Column('next_step', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=30), nullable=False),
    sa.Column('last_message', sa.Text(), nullable=True),
    sa.Column('final_answer', sa.Text(), nullable=True),
    sa.Column('error_code', sa.String(length=120), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('metadata_json', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('conversation_thread_id')
    )
    with op.batch_alter_table('conversation_sessions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_conversation_sessions_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_conversation_sessions_workspace_id'), ['workspace_id'], unique=False)
        batch_op.create_index('ix_conversation_sessions_workspace_user', ['workspace_id', 'user_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('conversation_sessions', schema=None) as batch_op:
        batch_op.drop_index('ix_conversation_sessions_workspace_user')
        batch_op.drop_index(batch_op.f('ix_conversation_sessions_workspace_id'))
        batch_op.drop_index(batch_op.f('ix_conversation_sessions_user_id'))

    op.drop_table('conversation_sessions')
