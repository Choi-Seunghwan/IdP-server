from abc import ABC, abstractmethod
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from datetime import datetime, UTC

from app.auth.model import RefreshToken


class RefreshTokenRepository(ABC):

    @abstractmethod
    async def create(self, refresh_token: RefreshToken) -> RefreshToken: ...

    @abstractmethod
    async def find_by_token(self, token: str) -> Optional[RefreshToken]: ...

    @abstractmethod
    async def revoke_by_token(self, token: str) -> None: ...

    @abstractmethod
    async def revoke_by_user_id(self, user_id: str) -> None: ...

    @abstractmethod
    async def delete_expired_tokens(self) -> None: ...


class RefreshTokenRepositoryImpl(RefreshTokenRepository):
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, refresh_token: RefreshToken) -> RefreshToken:
        """Refresh Token 생성"""
        self.db.add(refresh_token)
        await self.db.flush()
        await self.db.refresh(refresh_token)
        return refresh_token

    async def find_by_token(self, token: str) -> Optional[RefreshToken]:
        """토큰으로 조회"""
        result = await self.db.execute(
            select(RefreshToken)
            .where(RefreshToken.token == token)
            .where(RefreshToken.revoked_at.is_(None))  # 취소 안된 것만
        )
        return result.scalar_one_or_none()

    async def revoke_by_token(self, token: str) -> None:
        """특정 토큰 취소 (로그아웃)"""
        result = await self.db.execute(select(RefreshToken).where(RefreshToken.token == token))
        refresh_token = result.scalar_one_or_none()

        if refresh_token:
            refresh_token.revoked_at = datetime.now(UTC)
            await self.db.flush()

    async def revoke_by_user_id(self, user_id: str) -> None:
        """사용자의 모든 토큰 취소 (전체 로그아웃)"""
        result = await self.db.execute(
            select(RefreshToken)
            .where(RefreshToken.user_id == user_id)
            .where(RefreshToken.revoked_at.is_(None))
        )
        tokens = result.scalars().all()

        for token in tokens:
            token.revoked_at = datetime.now(UTC)

        await self.db.flush()

    async def delete_expired_tokens(self) -> None:
        """만료되거나 취소된 지 오래된 토큰 삭제 (배치 작업용)"""
        # 만료된 토큰 또는 30일 이상 취소된 토큰 삭제
        from datetime import timedelta

        thirty_days_ago = datetime.now(UTC) - timedelta(days=30)

        await self.db.execute(
            delete(RefreshToken).where(
                (RefreshToken.expires_at < datetime.now(UTC))
                | (RefreshToken.revoked_at < thirty_days_ago)
            )
        )
        await self.db.flush()
