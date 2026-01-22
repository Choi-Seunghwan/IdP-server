"""테스트용 Mock 객체 생성 팩토리"""
from datetime import datetime, UTC
from unittest.mock import MagicMock

from app.core.security import hash_password


def make_mock_user(
    id: str = "user-123",
    email: str = "test@example.com",
    password: str | None = "Password123!",
    username: str = "testuser",
    is_active: bool = True,
    is_verified: bool = False,
    phone_number: str | None = None,
    hashed_password: str | None = None,
) -> MagicMock:
    """Mock User 객체 생성"""
    user = MagicMock()
    user.id = id
    user.email = email
    user.username = username
    user.phone_number = phone_number
    user.is_active = is_active
    user.is_verified = is_verified
    user.hashed_password = hashed_password or (hash_password(password) if password else None)
    user.created_at = datetime.now(UTC)
    user.updated_at = datetime.now(UTC)
    return user
