from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.auth.persistence import RefreshTokenRepository, RefreshTokenRepositoryImpl
from app.auth.service import AuthService


def get_refresh_token_repository(db: AsyncSession = Depends(get_db)) -> RefreshTokenRepository:
    return RefreshTokenRepositoryImpl(db)


def get_auth_service(
    refresh_token_repository: RefreshTokenRepository = Depends(get_refresh_token_repository),
) -> AuthService:
    return AuthService(refresh_token_repository)
