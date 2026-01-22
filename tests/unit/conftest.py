"""Unit 테스트용 fixtures"""
import pytest
from unittest.mock import AsyncMock

from app.user.service import UserService


@pytest.fixture
def mock_repo():
    """Mock Repository (범용)"""
    return AsyncMock()


@pytest.fixture
def user_service(mock_repo):
    """Mock repository를 사용하는 UserService"""
    return UserService(mock_repo)
