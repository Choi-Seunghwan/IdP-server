import secrets

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import RedirectResponse

from app.core.dependencies import get_current_user_id_from_token
from app.core.state_manager import (
    save_oauth_state,
    verify_oauth_state,
    save_social_exchange_code,
)
from app.social.service import SocialService
from app.social.di import get_social_service
from app.social.dto import SocialLoginUrlDto, SocialAccountDto, ConnectSocialDto

router = APIRouter(prefix="/social", tags=["social"])


@router.get("/{provider}/login", response_model=SocialLoginUrlDto)
async def get_social_login_url(
    provider: str,
    redirect: str = Query(None),  # IdP 로그인 페이지에서 전달하는 redirect URL
    social_service: SocialService = Depends(get_social_service),
):
    """소셜 로그인 URL 생성"""
    state = secrets.token_urlsafe(32)  # CSRF 방지용 state

    # State를 Redis에 저장 (10분 만료)
    # redirect URL이 있으면 state에 포함하여 저장
    state_data = {"redirect": redirect} if redirect else {}
    await save_oauth_state(state, provider.lower(), state_data)

    return await social_service.get_authorization_url(provider, state)


@router.get("/{provider}/callback")
async def social_login_callback(
    provider: str,
    code: str = Query(...),
    state: str = Query(...),
    social_service: SocialService = Depends(get_social_service),
):
    """OAuth 콜백 처리"""
    # State 검증 (CSRF 공격 방지)
    state_data = await verify_oauth_state(state, provider.lower())

    # 소셜 로그인 처리
    login_result = await social_service.handle_callback(provider, code)

    # 항상 일회용 교환 코드 발급 (토큰을 직접 응답하지 않음)
    redirect_url = state_data.get("redirect") if state_data else None
    exchange_code = secrets.token_urlsafe(32)
    await save_social_exchange_code(
        code=exchange_code,
        access_token=login_result.access_token,
        refresh_token=login_result.refresh_token,
        redirect=redirect_url or "",
    )

    # redirect URL이 있으면 리다이렉트, 없으면 JSON으로 code 반환
    if redirect_url:
        return RedirectResponse(url=f"/api/oauth2/social-callback?code={exchange_code}")

    return {"code": exchange_code, "is_new_user": login_result.is_new_user}


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
