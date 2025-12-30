from fastapi import APIRouter, Depends, status, Response
from app.auth.service import AuthService
from app.auth.di import get_auth_service
from app.auth.dto import LoginDto, TokenDto, AccessTokenDto, RefreshTokenDto
from app.core.exceptions import UnauthorizedException
from datetime import UTC, datetime, timedelta


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenDto)
async def login(
    dto: LoginDto, response: Response, auth_service: AuthService = Depends(get_auth_service)
):
    """
    로그인
    SSO 플로우를 위해 쿠키에도 토큰 저장
    """
    token_dto = await auth_service.login(dto)

    # SSO 플로우를 위해 쿠키에도 토큰 저장
    # HttpOnly 쿠키로 설정하면 XSS 공격에 더 안전하지만,
    # 현재는 JavaScript에서도 접근 가능하도록 설정 (SameSite=Lax)
    expires = datetime.now(UTC) + timedelta(minutes=30)
    response.set_cookie(
        key="access_token",
        value=token_dto.access_token,
        expires=expires,
        path="/",
        httponly=True,
        samesite="lax",
        secure=True,
    )

    return token_dto


@router.post("/refresh", response_model=AccessTokenDto)
async def refresh_token(
    dto: RefreshTokenDto, auth_service: AuthService = Depends(get_auth_service)
):
    """Access Token 갱신"""
    return await auth_service.refresh(dto)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    dto: RefreshTokenDto,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
):
    """로그아웃 (현재 기기)"""
    await auth_service.logout(dto)
    # SSO 플로우를 위해 쿠키도 삭제 (설정 일치 필요)
    response.delete_cookie(
        key="access_token",
        path="/",
        samesite="lax",
        secure=False,  # 개발 환경에서는 false, 프로덕션에서는 true
    )


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    user_id: str,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
):
    """전체 로그아웃 (모든 기기)"""
    await auth_service.logout_all(user_id)
    # SSO 플로우를 위해 쿠키도 삭제 (설정 일치 필요)
    response.delete_cookie(
        key="access_token",
        path="/",
        samesite="lax",
        secure=False,  # 개발 환경에서는 false, 프로덕션에서는 true
    )
