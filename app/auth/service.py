import uuid
from datetime import UTC, datetime, timedelta

from app.auth.dto import LoginDto, RefreshTokenDto, TokenDto
from app.auth.model import RefreshToken
from app.auth.persistence import RefreshTokenRepository, hash_token
from app.config import settings
from app.core.exceptions import UnauthorizedException
from app.core.security import (
    create_access_token,
    create_refresh_token,
    verify_token,
)
from app.user.service import UserService


class AuthService:
    def __init__(self, user_service: UserService, refresh_token_repository: RefreshTokenRepository):
        self.user_service = user_service
        self.refresh_token_repository = refresh_token_repository

    async def login(self, dto: LoginDto) -> TokenDto:
        """로그인 (인증 + 토큰 발급)"""
        user = await self.user_service.authenticate_user(dto.email, dto.password)

        access_token = create_access_token(data={"sub": user.id, "email": user.email})

        # 새 토큰 family 시작
        family_id = str(uuid.uuid4())
        refresh_token_value = create_refresh_token(data={"sub": user.id})

        refresh_token_entity = RefreshToken(
            id=str(uuid.uuid4()),
            token_hash=hash_token(refresh_token_value),
            user_id=user.id,
            family_id=family_id,
            rotated_from=None,
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
        )
        await self.refresh_token_repository.create(refresh_token_entity)

        return TokenDto(
            access_token=access_token, refresh_token=refresh_token_value, token_type="bearer"
        )

    async def login_with_user_id(self, user_id: str, email: str | None) -> TokenDto:
        """이미 인증된 사용자로 토큰 발급 (소셜 로그인용)"""
        token_data: dict = {"sub": user_id}
        if email:
            token_data["email"] = email
        access_token = create_access_token(data=token_data)

        family_id = str(uuid.uuid4())
        refresh_token_value = create_refresh_token(data={"sub": user_id})

        refresh_token_entity = RefreshToken(
            id=str(uuid.uuid4()),
            token_hash=hash_token(refresh_token_value),
            user_id=user_id,
            family_id=family_id,
            rotated_from=None,
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
        )
        await self.refresh_token_repository.create(refresh_token_entity)

        return TokenDto(
            access_token=access_token, refresh_token=refresh_token_value, token_type="bearer"
        )

    async def refresh(self, dto: RefreshTokenDto) -> TokenDto:
        """Access Token 갱신 + Token Rotation"""
        # JWT 서명 검증
        payload = verify_token(dto.refresh_token, token_type="refresh")
        user_id = payload.get("sub")
        email = payload.get("email", "")

        if not user_id:
            raise UnauthorizedException(detail="Invalid token")

        # DB에서 토큰 조회 (해시로)
        token_hash = hash_token(dto.refresh_token)
        stored_token = await self.refresh_token_repository.find_by_token_hash(token_hash)

        # Reuse Detection: 이미 폐기된 토큰으로 요청 시
        if not stored_token:
            # 해당 토큰이 이전에 존재했는지 확인 (family 내에서)
            raise UnauthorizedException(detail="Invalid or revoked token")

        # 만료 확인
        expires_at = stored_token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at < datetime.now(UTC):
            raise UnauthorizedException(detail="Token expired")

        # Token Rotation. 기존 토큰 폐기 + 새 토큰 발급
        await self.refresh_token_repository.revoke_by_id(stored_token.id)

        # 새 Access Token
        access_token = create_access_token(data={"sub": user_id, "email": email})

        # 새 Refresh Token (같은 family 유지)
        new_refresh_token_value = create_refresh_token(data={"sub": user_id})
        new_refresh_token_entity = RefreshToken(
            id=str(uuid.uuid4()),
            token_hash=hash_token(new_refresh_token_value),
            user_id=user_id,
            family_id=stored_token.family_id,  # 같은 family
            rotated_from=stored_token.id,  # 이전 토큰 추적
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
        )
        await self.refresh_token_repository.create(new_refresh_token_entity)

        return TokenDto(
            access_token=access_token,
            refresh_token=new_refresh_token_value,
            token_type="bearer",
        )

    async def logout(self, dto: RefreshTokenDto) -> None:
        """로그아웃 (단일 토큰 폐기)"""
        token_hash = hash_token(dto.refresh_token)
        stored_token = await self.refresh_token_repository.find_by_token_hash(token_hash)
        if stored_token:
            await self.refresh_token_repository.revoke_by_id(stored_token.id)

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
