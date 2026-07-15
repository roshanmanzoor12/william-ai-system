"""add assistant_display_name and last_command_timing to voice_settings

Revision ID: 6e75f8f3baff
Revises: 4eff91e071d4
Create Date: 2026-07-19 09:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6e75f8f3baff'
down_revision: Union[str, None] = '4eff91e071d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('voice_settings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('assistant_display_name', sa.String(length=60), nullable=False, server_default='William'))
        batch_op.add_column(sa.Column('last_command_timing_json', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('voice_settings', schema=None) as batch_op:
        batch_op.drop_column('last_command_timing_json')
        batch_op.drop_column('assistant_display_name')
