"""increase refresh token length for rs256

Revision ID: increase_refresh_token_length
Revises: 107fbfb7cbaa
Create Date: 2025-12-29 01:30:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "increase_refresh_token_length"
down_revision: Union[str, None] = "107fbfb7cbaa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # RS256 토큰은 255자를 초과할 수 있으므로 Text 타입으로 변경
    op.alter_column(
        "refresh_tokens",
        "token",
        existing_type=sa.String(length=255),
        type_=sa.Text(),
        existing_nullable=False,
    )


def downgrade() -> None:
    # 다운그레이드 시 다시 String(255)로 변경
    op.alter_column(
        "refresh_tokens",
        "token",
        existing_type=sa.Text(),
        type_=sa.String(length=255),
        existing_nullable=False,
    )
