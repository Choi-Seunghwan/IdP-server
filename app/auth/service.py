from datetime import datetime, timedelta, UTC
import uuid

from app.auth.model import RefreshToken
from app.auth.dto import LoginDto, TokenDto, AccessTokenDto, RefreshTokenDto
from app.auth.persistence import RefreshTokenRepository
from app.user.service import UserService
from app.core.security import (
    create_access_token,
    create_refresh_token,
    verify_token,
)
from app.core.exceptions import UnauthorizedException
from app.config import settings


class AuthService:
    def __init__(self, user_service: UserService, refresh_token_repository: RefreshTokenRepository):
        self.user_service = user_service
        self.refresh_token_repository = refresh_token_repository

    async def login(self, dto: LoginDto) -> TokenDto:
        """로그인 (인증 + 토큰 발급)"""
        # 사용자 인증 위임 (UserService)
        user = await self.user_service.authenticate_user(dto.email, dto.password)

        # Access Token 생성
        access_token = create_access_token(data={"sub": user.id, "email": user.email})

        # Refresh Token 생성 및 저장
        refresh_token_value = create_refresh_token(data={"sub": user.id})

        refresh_token_entity = RefreshToken(
            id=str(uuid.uuid4()),
            token=refresh_token_value,
            user_id=user.id,
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
        )
        await self.refresh_token_repository.create(refresh_token_entity)

        return TokenDto(
            access_token=access_token, refresh_token=refresh_token_value, token_type="bearer"
        )

    async def login_with_user_id(self, user_id: str, email: str) -> TokenDto:
        """
        이미 인증된 사용자로 토큰 발급 (소셜 로그인용)
        비밀번호 검증 없이 user_id로 바로 토큰 발급
        """
        # Access Token 생성
        access_token = create_access_token(data={"sub": user_id, "email": email})

        # Refresh Token 생성 및 저장
        refresh_token_value = create_refresh_token(data={"sub": user_id})

        refresh_token_entity = RefreshToken(
            id=str(uuid.uuid4()),
            token=refresh_token_value,
            user_id=user_id,
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
        )
        await self.refresh_token_repository.create(refresh_token_entity)

        return TokenDto(
            access_token=access_token, refresh_token=refresh_token_value, token_type="bearer"
        )

    async def refresh(self, dto: RefreshTokenDto) -> AccessTokenDto:
        """Access Token 갱신"""
        # Refresh Token 검증
        payload = verify_token(dto.refresh_token, token_type="refresh")
        user_id = payload.get("sub")
        email = payload.get("email", "")

        if not user_id:
            raise UnauthorizedException(detail="Invalid token")

        # DB에서 Refresh Token 확인
        stored_token = await self.refresh_token_repository.find_by_token(dto.refresh_token)
        if not stored_token:
            raise UnauthorizedException(detail="Invalid or revoked token")

        expires_at = stored_token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at < datetime.now(UTC):
            raise UnauthorizedException(detail="Token expired")

        # 새 Access Token 발급
        access_token = create_access_token(data={"sub": user_id, "email": email})

        return AccessTokenDto(access_token=access_token, token_type="bearer")

    async def logout(self, dto: RefreshTokenDto) -> None:
        """로그아웃 (단일 기기)"""
        await self.refresh_token_repository.revoke_by_token(dto.refresh_token)

    async def logout_all(self, user_id: str) -> None:
        """전체 로그아웃 (모든 기기)"""
        await self.refresh_token_repository.revoke_by_user_id(user_id)

    async def get_current_user_id(self, access_token: str) -> str:
        """Access Token에서 사용자 ID 추출"""
        payload = verify_token(access_token, token_type="access")
        user_id = payload.get("sub")

        if not user_id:
            raise UnauthorizedException(detail="Invalid token")

        return user_id
