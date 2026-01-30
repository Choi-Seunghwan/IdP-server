import json
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Optional

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.sso.model import AuthorizationCode, OAuth2Client


# ============================================
# OAuth2Client Repository
# ============================================


class OAuth2ClientRepository(ABC):
    """OAuth2 Client Repository 인터페이스"""

    @abstractmethod
    async def create(self, client: OAuth2Client) -> OAuth2Client: ...

    @abstractmethod
    async def find_by_id(self, client_id: str) -> Optional[OAuth2Client]: ...

    @abstractmethod
    async def find_by_client_id(self, client_id: str) -> Optional[OAuth2Client]: ...

    @abstractmethod
    async def update(self, client: OAuth2Client) -> OAuth2Client: ...

    @abstractmethod
    async def delete(self, client: OAuth2Client) -> None: ...

    @abstractmethod
    async def exists_by_client_id(self, client_id: str) -> bool: ...


class OAuth2ClientRepositoryImpl(OAuth2ClientRepository):
    """OAuth2 Client Repository 구현체"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, client: OAuth2Client) -> OAuth2Client:
        self.db.add(client)
        await self.db.flush()
        await self.db.refresh(client)
        return client

    async def find_by_id(self, client_id: str) -> Optional[OAuth2Client]:
        result = await self.db.execute(select(OAuth2Client).where(OAuth2Client.id == client_id))
        return result.scalar_one_or_none()

    async def find_by_client_id(self, client_id: str) -> Optional[OAuth2Client]:
        result = await self.db.execute(
            select(OAuth2Client).where(OAuth2Client.client_id == client_id)
        )
        return result.scalar_one_or_none()

    async def update(self, client: OAuth2Client) -> OAuth2Client:
        await self.db.flush()
        await self.db.refresh(client)
        return client

    async def delete(self, client: OAuth2Client) -> None:
        await self.db.delete(client)
        await self.db.flush()

    async def exists_by_client_id(self, client_id: str) -> bool:
        result = await self.db.execute(
            select(OAuth2Client).where(OAuth2Client.client_id == client_id)
        )
        return result.scalar_one_or_none() is not None


# ============================================
# AuthorizationCode Repository
# ============================================


class AuthorizationCodeRepository(ABC):
    """Authorization Code Repository 인터페이스"""

    @abstractmethod
    async def create(self, code: AuthorizationCode) -> AuthorizationCode: ...

    @abstractmethod
    async def find_by_code(self, code: str) -> Optional[AuthorizationCode]: ...

    @abstractmethod
    async def delete(self, code: AuthorizationCode) -> None: ...

    @abstractmethod
    async def mark_as_used(self, code: AuthorizationCode) -> None: ...


class AuthorizationCodeRepositoryImpl(AuthorizationCodeRepository):
    """Redis 기반 Authorization Code Repository 구현체"""

    CODE_PREFIX = "oauth:code:"

    def __init__(self, redis: Redis):
        self.redis = redis

    def _key(self, code: str) -> str:
        return f"{self.CODE_PREFIX}{code}"

    def _serialize(self, auth_code: AuthorizationCode) -> str:
        return json.dumps(
            {
                "id": auth_code.id,
                "code": auth_code.code,
                "client_id": auth_code.client_id,
                "user_id": auth_code.user_id,
                "redirect_uri": auth_code.redirect_uri,
                "scopes": auth_code.scopes,
                "code_challenge": auth_code.code_challenge,
                "code_challenge_method": auth_code.code_challenge_method,
                "state": auth_code.state,
                "expires_at": auth_code.expires_at.isoformat(),
                "is_used": auth_code.is_used,
                "created_at": (
                    auth_code.created_at.isoformat()
                    if auth_code.created_at
                    else datetime.now(UTC).isoformat()
                ),
            }
        )

    def _deserialize(self, data: str) -> AuthorizationCode:
        obj = json.loads(data)
        return AuthorizationCode(
            id=obj["id"],
            code=obj["code"],
            client_id=obj["client_id"],
            user_id=obj["user_id"],
            redirect_uri=obj["redirect_uri"],
            scopes=obj["scopes"],
            code_challenge=obj.get("code_challenge"),
            code_challenge_method=obj.get("code_challenge_method"),
            state=obj.get("state"),
            expires_at=datetime.fromisoformat(obj["expires_at"]),
            is_used=obj["is_used"],
            created_at=datetime.fromisoformat(obj["created_at"]),
        )

    async def create(self, auth_code: AuthorizationCode) -> AuthorizationCode:
        """Authorization Code 생성 (TTL 10분)"""
        ttl_seconds = int((auth_code.expires_at - datetime.now(UTC)).total_seconds())
        if ttl_seconds <= 0:
            ttl_seconds = 1

        await self.redis.setex(
            self._key(auth_code.code),
            ttl_seconds,
            self._serialize(auth_code),
        )
        return auth_code

    async def find_by_code(self, code: str) -> Optional[AuthorizationCode]:
        """코드로 조회"""
        data = await self.redis.get(self._key(code))
        if not data:
            return None
        return self._deserialize(data)

    async def delete(self, auth_code: AuthorizationCode) -> None:
        """코드 삭제"""
        await self.redis.delete(self._key(auth_code.code))

    async def mark_as_used(self, auth_code: AuthorizationCode) -> None:
        """사용 처리 후 즉시 삭제 (1회용)"""
        await self.redis.delete(self._key(auth_code.code))
