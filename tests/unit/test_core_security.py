import pytest
from datetime import timedelta
from freezegun import freeze_time
from jose import jwt

from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_token,
)
from app.core.exceptions import UnauthorizedException

pytestmark = pytest.mark.unit


class TestHashPassword:
    """비밀번호 해싱 테스트"""

    def test_hash_password(self):
        """비밀번호 해싱"""
        password = "MySecurePassword123!"
        hashed = hash_password(password)

        assert hashed is not None
        assert hashed != password

    def test_hash_different_salts(self):
        """같은 비밀번호도 다른 해시 생성"""
        password = "SamePassword123"
        assert hash_password(password) != hash_password(password)


class TestVerifyPassword:
    """비밀번호 검증 테스트"""

    def test_verify_success(self):
        """올바른 비밀번호 검증"""
        password = "MySecurePassword123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_failure(self):
        """잘못된 비밀번호 검증"""
        hashed = hash_password("MySecurePassword123!")
        assert verify_password("WrongPassword", hashed) is False


class TestCreateAccessToken:
    """Access Token 생성 테스트"""

    def test_create_access_token(self, monkeypatch, test_settings):
        """Access Token 생성 및 디코딩"""
        monkeypatch.setattr("app.core.security.settings", test_settings)

        token = create_access_token({"sub": "user-123", "email": "test@example.com"})

        decoded = jwt.decode(token, test_settings.secret_key, algorithms=[test_settings.algorithm])
        assert decoded["sub"] == "user-123"
        assert decoded["type"] == "access"


class TestCreateRefreshToken:
    """Refresh Token 생성 테스트"""

    def test_create_refresh_token(self, monkeypatch, test_settings):
        """Refresh Token 생성"""
        test_settings.rsa_private_key = ""
        test_settings.rsa_public_key = ""
        monkeypatch.setattr("app.core.security.settings", test_settings)

        token = create_refresh_token({"sub": "user-123"})

        decoded = jwt.decode(token, test_settings.secret_key, algorithms=[test_settings.algorithm])
        assert decoded["sub"] == "user-123"
        assert decoded["type"] == "refresh"


class TestDecodeToken:
    """토큰 디코딩 테스트"""

    def test_decode_success(self, monkeypatch, test_settings):
        """유효한 토큰 디코딩"""
        monkeypatch.setattr("app.core.security.settings", test_settings)

        token = create_access_token({"sub": "user-123"})
        decoded = decode_token(token)
        assert decoded["sub"] == "user-123"

    def test_decode_expired(self, monkeypatch, test_settings):
        """만료된 토큰"""
        monkeypatch.setattr("app.core.security.settings", test_settings)

        with freeze_time("2024-01-01 12:00:00"):
            token = create_access_token({"sub": "user-123"}, expires_delta=timedelta(minutes=30))

        with freeze_time("2024-01-01 13:00:00"):
            with pytest.raises(UnauthorizedException):
                decode_token(token)

    def test_decode_invalid(self, monkeypatch, test_settings):
        """잘못된 토큰"""
        monkeypatch.setattr("app.core.security.settings", test_settings)

        with pytest.raises(UnauthorizedException):
            decode_token("invalid.token.here")


class TestVerifyToken:
    """토큰 타입 검증 테스트"""

    def test_verify_access_token(self, monkeypatch, test_settings):
        """Access Token 타입 검증"""
        monkeypatch.setattr("app.core.security.settings", test_settings)

        token = create_access_token({"sub": "user-123"})
        payload = verify_token(token, token_type="access")
        assert payload["type"] == "access"

    def test_verify_type_mismatch(self, monkeypatch, test_settings):
        """토큰 타입 불일치"""
        monkeypatch.setattr("app.core.security.settings", test_settings)

        token = create_access_token({"sub": "user-123"})
        with pytest.raises(UnauthorizedException):
            verify_token(token, token_type="refresh")
