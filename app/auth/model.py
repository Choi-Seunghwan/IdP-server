import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.user.model import User


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # SHA-256 해시
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

    # Token Rotation 지원
    family_id: Mapped[str] = mapped_column(String(36), index=True)  # 토큰 체인 식별자
    rotated_from: Mapped[str | None] = mapped_column(String(36), nullable=True)  # 이전 토큰 ID

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    # Relationship
    user: Mapped["User"] = relationship(back_populates="refresh_tokens")
