import uuid

from app.social.model import SocialAccount, SocialProvider
from app.social.dto import (
    SocialLoginUrlDto,
    SocialLoginDto,
    SocialAccountDto,
    OAuthUserInfo,
)
from app.social.persistence import SocialAccountRepository
from app.user.service import UserService
from app.auth.service import AuthService
from app.core.exceptions import BadRequestException, NotFoundException


class SocialService:
    def __init__(
        self,
        social_account_repository: SocialAccountRepository,
        user_service: UserService,
        auth_service: AuthService,
    ):
        self.social_account_repository = social_account_repository
        self.user_service = user_service
        self.auth_service = auth_service

    async def get_authorization_url(self, provider: str, state: str) -> SocialLoginUrlDto:
        """OAuth 인증 URL 생성"""
        from app.social.providers.google import GoogleOAuthProvider
        from app.social.providers.kakao import KakaoOAuthProvider
        from app.social.providers.naver import NaverOAuthProvider

        providers_map = {
            "google": GoogleOAuthProvider,
            "kakao": KakaoOAuthProvider,
            "naver": NaverOAuthProvider,
        }

        provider_class = providers_map.get(provider.lower())
        if not provider_class:
            raise BadRequestException(detail=f"Unsupported provider: {provider}")

        auth_url = provider_class.get_authorization_url(state)
        return SocialLoginUrlDto(authorization_url=auth_url)

    async def handle_callback(self, provider: str, code: str) -> SocialLoginDto:
        """OAuth 콜백 처리 및 로그인/회원가입"""
        # 1. Authorization code로 사용자 정보 획득
        user_info = await self._get_oauth_user_info(provider, code)

        # 2. 소셜 계정 조회
        provider_enum = SocialProvider(provider.lower())
        social_account = await self.social_account_repository.find_by_provider_and_user_id(
            provider_enum, user_info.provider_user_id
        )

        is_new_user = False
        user_id: str
        email: str

        if social_account:
            # 기존 사용자 로그인
            user = await self.user_service.get_user_by_id(social_account.user_id)
            user_id = user.id
            email = user.email
        else:
            # 신규 사용자 생성
            user = await self._create_user_from_oauth(user_info)
            social_account = await self._create_social_account(user.id, provider_enum, user_info)
            user_id = user.id
            email = user.email
            is_new_user = True

        # 3. 토큰 발급 (AuthService 위임)
        tokens = await self.auth_service.login_with_user_id(user_id, email)

        return SocialLoginDto(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_type=tokens.token_type,
            is_new_user=is_new_user,
        )

    async def connect_social_account(
        self, user_id: str, provider: str, code: str
    ) -> SocialAccountDto:
        """기존 사용자에게 소셜 계정 연결"""
        # 사용자 존재 확인 (UserService 사용)
        user = await self.user_service.get_user_by_id(user_id)

        # OAuth 사용자 정보 획득
        user_info = await self._get_oauth_user_info(provider, code)

        # 이미 연결된 소셜 계정인지 확인
        provider_enum = SocialProvider(provider.lower())
        existing = await self.social_account_repository.find_by_provider_and_user_id(
            provider_enum, user_info.provider_user_id
        )
        if existing:
            raise BadRequestException(detail="This social account is already connected")

        # 소셜 계정 생성
        social_account = await self._create_social_account(user_id, provider_enum, user_info)

        return SocialAccountDto.model_validate(social_account)

    async def get_user_social_accounts(self, user_id: str) -> list[SocialAccountDto]:
        """사용자의 연결된 소셜 계정 목록 조회"""
        social_accounts = await self.social_account_repository.find_by_user_id(user_id)
        return [SocialAccountDto.model_validate(sa) for sa in social_accounts]

    async def disconnect_social_account(self, user_id: str, social_account_id: str) -> None:
        """소셜 계정 연결 해제"""
        # 소셜 계정 목록 조회
        social_accounts = await self.social_account_repository.find_by_user_id(user_id)

        # 최소 1개는 남겨야 함 (비밀번호 없는 경우)
        has_password = await self.user_service.has_password(user_id)

        if not has_password and len(social_accounts) <= 1:
            raise BadRequestException(
                detail="Cannot disconnect the last social account without password"
            )

        # 해당 소셜 계정 찾아서 삭제
        for sa in social_accounts:
            if sa.id == social_account_id:
                await self.social_account_repository.delete(sa)
                return

        raise NotFoundException(detail="Social account not found")

    async def _get_oauth_user_info(self, provider: str, code: str) -> OAuthUserInfo:
        """OAuth Provider로부터 사용자 정보 획득"""
        from app.social.providers.google import GoogleOAuthProvider
        from app.social.providers.kakao import KakaoOAuthProvider
        from app.social.providers.naver import NaverOAuthProvider

        providers_map = {
            "google": GoogleOAuthProvider,
            "kakao": KakaoOAuthProvider,
            "naver": NaverOAuthProvider,
        }

        provider_class = providers_map.get(provider.lower())
        if not provider_class:
            raise BadRequestException(detail=f"Unsupported provider: {provider}")

        access_token = await provider_class.get_access_token(code)
        return await provider_class.get_user_info(access_token)

    async def _create_user_from_oauth(self, user_info: OAuthUserInfo):
        """OAuth 정보로 새 사용자 생성"""
        email = user_info.email or f"user_{uuid.uuid4().hex[:8]}@social.local"
        return await self.user_service.create_social_user(email, user_info.name)

    async def _create_social_account(
        self, user_id: str, provider: SocialProvider, user_info: OAuthUserInfo
    ) -> SocialAccount:
        """소셜 계정 생성"""
        social_account = SocialAccount(
            id=str(uuid.uuid4()),
            user_id=user_id,
            provider=provider,
            provider_user_id=user_info.provider_user_id,
            email=user_info.email,
        )
        return await self.social_account_repository.create(social_account)
