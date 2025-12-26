from datetime import UTC, datetime, timedelta
import uuid
from app.auth.dto import AccessTokenDto, RefreshTokenDto, TokenDto
from app.auth.model import RefreshToken
from app.auth.persistence import RefreshTokenRepository
from app.config import Settings
from app.core.exceptions import UnauthorizedException
from app.core.security import create_access_token, create_refresh_token, verify_token
from app.user.persistence import UserRepository


class AuthService:
    def __init__(self, refresh_token_repository: RefreshTokenRepository) -> None:
        self.refresh_token_repository = refresh_token_repository

    async def login(self, user_id: str, email: str) -> TokenDto:
        """로그인. 토큰 발급"""
        # Access Token 생성
        access_token = create_access_token(data={"sub": user_id, "email": email})

        # Refresh Token 생성 및 저장
        refresh_token_value = create_refresh_token(data={"sub": user_id})

        refresh_token_entity = RefreshToken(
            id=str(uuid.uuid4()),
            token=refresh_token_value,
            user_id=user_id,
            expires_at=datetime.now(UTC) + timedelta(days=Settings.refresh_token_expire_days),
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

        if not user_id:
            raise UnauthorizedException(detail="invalid token")

        stored_token = await self.refresh_token_repository.find_by_token(dto.refresh_token)

        # DB 에서 Refresh Token 확인
        if not stored_token:
            raise UnauthorizedException(detail="invalid or revoked token")

        # 만료 확인
        if stored_token.expires_at < datetime.now(UTC):
            raise UnauthorizedException(detail="token expired")

        # 사용자 정보는 토큰에서 가져옴 (DB 조회 최소화)
        email = payload.get("email", "")

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
            raise UnauthorizedException(detail="invalid token")

        return user_id
