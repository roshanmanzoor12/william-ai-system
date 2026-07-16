"""add trusted voice profile fields (device_id, embedding, last_verified_at)

Revision ID: c19f2a7de053
Revises: b8453d9a2086
Create Date: 2026-07-21 09:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c19f2a7de053'
down_revision: Union[str, None] = 'b8453d9a2086'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('voice_identity_profiles', schema=None) as batch_op:
        batch_op.add_column(sa.Column('device_id', sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column('embedding_encrypted', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('embedding_provider', sa.String(length=60), nullable=True))
        batch_op.add_column(sa.Column('last_verified_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index('ix_voice_identity_profiles_last_verified', ['last_verified_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('voice_identity_profiles', schema=None) as batch_op:
        batch_op.drop_index('ix_voice_identity_profiles_last_verified')
        batch_op.drop_column('last_verified_at')
        batch_op.drop_column('embedding_provider')
        batch_op.drop_column('embedding_encrypted')
        batch_op.drop_column('device_id')
