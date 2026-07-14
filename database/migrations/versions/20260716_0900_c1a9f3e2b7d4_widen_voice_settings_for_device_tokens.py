"""widen voice_settings for voice worker device tokens

Revision ID: c1a9f3e2b7d4
Revises: 9896d7628cf9
Create Date: 2026-07-16 09:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1a9f3e2b7d4'
down_revision: Union[str, None] = '9896d7628cf9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('voice_settings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('device_id', sa.String(length=80), nullable=True))
        batch_op.add_column(sa.Column('device_name', sa.String(length=140), nullable=True))
        batch_op.add_column(sa.Column('device_platform', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('device_owner_user_id', sa.String(length=140), nullable=True))
        batch_op.add_column(sa.Column('device_token_hash', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('device_token_status', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('supported_features_json', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('setup_completed_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index(
            batch_op.f('ix_voice_settings_device_token_hash'), ['device_token_hash'], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table('voice_settings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_voice_settings_device_token_hash'))
        batch_op.drop_column('setup_completed_at')
        batch_op.drop_column('supported_features_json')
        batch_op.drop_column('device_token_status')
        batch_op.drop_column('device_token_hash')
        batch_op.drop_column('device_owner_user_id')
        batch_op.drop_column('device_platform')
        batch_op.drop_column('device_name')
        batch_op.drop_column('device_id')
