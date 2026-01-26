import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import RedirectResponse

from app.core.dependencies import get_current_user_id_from_token
from app.core.state_manager import save_oauth_state, verify_oauth_state
from app.social.service import SocialService
from app.social.di import get_social_service
from app.social.dto import SocialLoginUrlDto, SocialAccountDto, ConnectSocialDto

router = APIRouter(prefix="/social", tags=["social"])


@router.get("/{provider}/login", response_model=SocialLoginUrlDto)
async def get_social_login_url(
    provider: str,
    redirect: str = Query(None),  # IdP 로그인 페이지에서 전달하는 redirect URL
    social_service: SocialService = Depends(get_social_service)
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
    
    # redirect URL이 있으면 (IdP 로그인 페이지에서 온 경우)
    if state_data and state_data.get("redirect"):
        redirect_url = state_data["redirect"]
        
        # HTML 페이지로 리다이렉트하여 토큰 저장 후 원래 URL로 이동
        # 토큰을 쿼리 파라미터로 전달 (보안상 완벽하지 않지만 동작함)
        # 더 나은 방법: 세션 또는 쿠키 사용
        token_params = urlencode({
            "access_token": login_result.access_token,
            "refresh_token": login_result.refresh_token,
            "redirect": redirect_url
        })
        return RedirectResponse(url=f"/api/oauth2/social-callback?{token_params}")
    
    # 일반 API 응답 (JSON)
    return login_result


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
