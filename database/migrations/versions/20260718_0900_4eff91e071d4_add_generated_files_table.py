"""add generated_files table

Revision ID: 4eff91e071d4
Revises: e2b4a91f6c3d
Create Date: 2026-07-18 09:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4eff91e071d4'
down_revision: Union[str, None] = 'e2b4a91f6c3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('generated_files',
    sa.Column('file_id', sa.String(length=140), nullable=False),
    sa.Column('user_id', sa.String(length=140), nullable=False),
    sa.Column('workspace_id', sa.String(length=140), nullable=False),
    sa.Column('filename', sa.String(length=255), nullable=False),
    sa.Column('content_type', sa.String(length=140), nullable=False),
    sa.Column('file_type', sa.String(length=30), nullable=False),
    sa.Column('size_bytes', sa.Integer(), nullable=False),
    sa.Column('storage_key', sa.String(length=400), nullable=False),
    sa.Column('generated_by_agent', sa.String(length=60), nullable=False),
    sa.Column('source_prompt', sa.Text(), nullable=True),
    sa.Column('conversation_thread_id', sa.String(length=80), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('file_id'),
    sa.UniqueConstraint('storage_key')
    )
    with op.batch_alter_table('generated_files', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_generated_files_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_generated_files_workspace_id'), ['workspace_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_generated_files_conversation_thread_id'), ['conversation_thread_id'], unique=False)
        batch_op.create_index('ix_generated_files_workspace_user', ['workspace_id', 'user_id'], unique=False)
        batch_op.create_index('ix_generated_files_workspace_created', ['workspace_id', 'created_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('generated_files', schema=None) as batch_op:
        batch_op.drop_index('ix_generated_files_workspace_created')
        batch_op.drop_index('ix_generated_files_workspace_user')
        batch_op.drop_index(batch_op.f('ix_generated_files_conversation_thread_id'))
        batch_op.drop_index(batch_op.f('ix_generated_files_workspace_id'))
        batch_op.drop_index(batch_op.f('ix_generated_files_user_id'))

    op.drop_table('generated_files')
