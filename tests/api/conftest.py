"""API 테스트용 fixtures"""
import pytest


@pytest.fixture
def auth_headers():
    """인증 헤더 생성 헬퍼"""
    def _headers(token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}
    return _headers
