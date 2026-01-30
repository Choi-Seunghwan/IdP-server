from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.di import get_refresh_token_repository
from app.auth.persistence import RefreshTokenRepository
from app.core.database import get_db
from app.core.redis import get_redis
from app.sso.client_service import ClientService
from app.sso.persistence import (
    AuthorizationCodeRepository,
    AuthorizationCodeRepositoryImpl,
    OAuth2ClientRepository,
    OAuth2ClientRepositoryImpl,
)
from app.sso.service import SSOService
from app.user.di import get_user_service
from app.user.service import UserService


# ============================================
# Repository 의존성
# ============================================


def get_oauth2_client_repository(
    db: AsyncSession = Depends(get_db),
) -> OAuth2ClientRepository:
    """OAuth2 Client Repository 주입"""
    return OAuth2ClientRepositoryImpl(db)


async def get_authorization_code_repository(
    redis: Redis = Depends(get_redis),
) -> AuthorizationCodeRepository:
    """Authorization Code Repository 주입 (Redis)"""
    return AuthorizationCodeRepositoryImpl(redis)


# ============================================
# Service 의존성
# ============================================


def get_client_service(
    client_repository: OAuth2ClientRepository = Depends(get_oauth2_client_repository),
) -> ClientService:
    """Client Service 주입"""
    return ClientService(client_repository)


def get_sso_service(
    client_service: ClientService = Depends(get_client_service),
    user_service: UserService = Depends(get_user_service),
    auth_code_repository: AuthorizationCodeRepository = Depends(get_authorization_code_repository),
    refresh_token_repository: RefreshTokenRepository = Depends(get_refresh_token_repository),
) -> SSOService:
    """SSO Service 주입"""
    return SSOService(
        client_service=client_service,
        user_service=user_service,
        auth_code_repository=auth_code_repository,
        refresh_token_repository=refresh_token_repository,
    )
