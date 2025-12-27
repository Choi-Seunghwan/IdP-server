from abc import ABC, abstractmethod
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.sso.model import OAuth2Client, AuthorizationCode


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
        result = await self.db.execute(
            select(OAuth2Client).where(OAuth2Client.id == client_id)
        )
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
    """Authorization Code Repository 구현체"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, code: AuthorizationCode) -> AuthorizationCode:
        self.db.add(code)
        await self.db.flush()
        await self.db.refresh(code)
        return code

    async def find_by_code(self, code: str) -> Optional[AuthorizationCode]:
        result = await self.db.execute(
            select(AuthorizationCode).where(AuthorizationCode.code == code)
        )
        return result.scalar_one_or_none()

    async def delete(self, code: AuthorizationCode) -> None:
        await self.db.delete(code)
        await self.db.flush()

    async def mark_as_used(self, code: AuthorizationCode) -> None:
        code.is_used = True
        await self.db.flush()

