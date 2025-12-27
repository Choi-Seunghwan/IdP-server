from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.social.persistence import SocialAccountRepository, SocialAccountRepositoryImpl
from app.social.service import SocialService
from app.user.service import UserService
from app.user.di import get_user_service
from app.auth.service import AuthService
from app.auth.di import get_auth_service


def get_social_account_repository(db: AsyncSession = Depends(get_db)) -> SocialAccountRepository:
    """SocialAccountRepository 의존성 주입"""
    return SocialAccountRepositoryImpl(db)


def get_social_service(
    social_account_repository: SocialAccountRepository = Depends(get_social_account_repository),
    user_service: UserService = Depends(get_user_service),
    auth_service: AuthService = Depends(get_auth_service),
) -> SocialService:
    """SocialService 의존성 주입"""
    return SocialService(social_account_repository, user_service, auth_service)
