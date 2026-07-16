"""add pending_mode to voice_settings

Revision ID: b8453d9a2086
Revises: 6e75f8f3baff
Create Date: 2026-07-20 09:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8453d9a2086'
down_revision: Union[str, None] = '6e75f8f3baff'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('voice_settings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('pending_mode', sa.String(length=40), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('voice_settings', schema=None) as batch_op:
        batch_op.drop_column('pending_mode')
