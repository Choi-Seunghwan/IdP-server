from fastapi import APIRouter, Depends, Query, status
from app.core.dependencies import get_current_user_id_from_token
from app.core.state_manager import save_oauth_state, verify_oauth_state
from app.social.service import SocialService
from app.social.di import get_social_service
from app.social.dto import SocialLoginUrlDto, SocialLoginDto, SocialAccountDto, ConnectSocialDto
import secrets

router = APIRouter(prefix="/social", tags=["social"])


@router.get("/{provider}/login", response_model=SocialLoginUrlDto)
async def get_social_login_url(
    provider: str,
    social_service: SocialService = Depends(get_social_service)
):
    """소셜 로그인 URL 생성"""
    state = secrets.token_urlsafe(32)  # CSRF 방지용 state
    # State를 Redis에 저장 (10분 만료)
    await save_oauth_state(state, provider.lower())
    return await social_service.get_authorization_url(provider, state)


@router.get("/{provider}/callback", response_model=SocialLoginDto)
async def social_login_callback(
    provider: str,
    code: str = Query(...),
    state: str = Query(...),
    social_service: SocialService = Depends(get_social_service),
):
    """OAuth 콜백 처리"""
    # State 검증 (CSRF 공격 방지)
    await verify_oauth_state(state, provider.lower())
    return await social_service.handle_callback(provider, code)


@router.post("/connect", response_model=SocialAccountDto)
async def connect_social_account(
    dto: ConnectSocialDto,
    current_user_id: str = Depends(get_current_user_id_from_token),
    social_service: SocialService = Depends(get_social_service),
):
    """기존 사용자에 소셜 계정 연결"""
    return await social_service.connect_social_account(current_user_id, dto.provider, dto.code)


@router.get("/accounts", response_model=list[SocialAccountDto])
async def get_my_social_accounts(
    current_user_id: str = Depends(get_current_user_id_from_token),
    social_service: SocialService = Depends(get_social_service),
):
    """내 소셜 계정 목록 조회"""
    return await social_service.get_user_social_accounts(current_user_id)


@router.delete("/accounts/{social_account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disconnect_social_account(
    social_account_id: str,
    current_user_id: str = Depends(get_current_user_id_from_token),
    social_service: SocialService = Depends(get_social_service),
):
    """소셜 계정 연결 해제"""
    await social_service.disconnect_social_account(current_user_id, social_account_id)
