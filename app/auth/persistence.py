import hashlib
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.model import RefreshToken


def hash_token(token: str) -> str:
    """토큰을 SHA-256으로 해시"""
    return hashlib.sha256(token.encode()).hexdigest()


class RefreshTokenRepository(ABC):
    """Refresh Token Repository 인터페이스"""

    @abstractmethod
    async def create(self, refresh_token: RefreshToken) -> RefreshToken: ...

    @abstractmethod
    async def find_by_token_hash(self, token_hash: str) -> Optional[RefreshToken]: ...

    @abstractmethod
    async def revoke_by_id(self, token_id: str) -> None: ...

    @abstractmethod
    async def revoke_by_user_id(self, user_id: str) -> None: ...

    @abstractmethod
    async def revoke_family(self, family_id: str) -> None:
        """토큰 family 전체 폐기 (reuse detection 시)"""
        ...

    @abstractmethod
    async def find_by_family_id(self, family_id: str) -> list[RefreshToken]: ...


class RefreshTokenRepositoryImpl(RefreshTokenRepository):
    """Refresh Token Repository 구현체"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, refresh_token: RefreshToken) -> RefreshToken:
        """Refresh Token 생성"""
        self.db.add(refresh_token)
        await self.db.flush()
        await self.db.refresh(refresh_token)
        return refresh_token

    async def find_by_token_hash(self, token_hash: str) -> Optional[RefreshToken]:
        """토큰 해시로 조회 (취소되지 않은 것만)"""
        result = await self.db.execute(
            select(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .where(RefreshToken.revoked_at.is_(None))
        )
        return result.scalar_one_or_none()

    async def revoke_by_id(self, token_id: str) -> None:
        """특정 토큰 폐기"""
        result = await self.db.execute(
            select(RefreshToken).where(RefreshToken.id == token_id)
        )
        refresh_token = result.scalar_one_or_none()

        if refresh_token:
            refresh_token.revoked_at = datetime.now(UTC)
            await self.db.flush()

    async def revoke_by_user_id(self, user_id: str) -> None:
        """사용자의 모든 토큰 폐기 (전체 로그아웃)"""
        result = await self.db.execute(
            select(RefreshToken)
            .where(RefreshToken.user_id == user_id)
            .where(RefreshToken.revoked_at.is_(None))
        )
        tokens = result.scalars().all()

        for token in tokens:
            token.revoked_at = datetime.now(UTC)

        await self.db.flush()

    async def revoke_family(self, family_id: str) -> None:
        """토큰 family 전체 폐기 (reuse detection 시)"""
        result = await self.db.execute(
            select(RefreshToken)
            .where(RefreshToken.family_id == family_id)
            .where(RefreshToken.revoked_at.is_(None))
        )
        tokens = result.scalars().all()

        for token in tokens:
            token.revoked_at = datetime.now(UTC)

        await self.db.flush()

    async def find_by_family_id(self, family_id: str) -> list[RefreshToken]:
        """family_id로 토큰 목록 조회"""
        result = await self.db.execute(
            select(RefreshToken).where(RefreshToken.family_id == family_id)
        )
        return list(result.scalars().all())

    async def delete_expired_tokens(self) -> None:
        """만료된 토큰 삭제 (배치 작업용)"""
        await self.db.execute(
            delete(RefreshToken).where(RefreshToken.expires_at < datetime.now(UTC))
        )
        await self.db.flush()
