from fastapi import APIRouter, Depends, status
from app.auth.service import AuthService
from app.auth.di import get_auth_service
from app.auth.dto import LoginDto, TokenDto, AccessTokenDto, RefreshTokenDto
from app.user.service import UserService
from app.user.di import get_user_service
from app.core.security import verify_password
from app.core.exceptions import UnauthorizedException


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenDto)
async def login(dto: LoginDto, auth_service: AuthService = Depends()):
    """로그인"""
    return await auth_service.login(dto)


@router.post("/refresh", response_model=AccessTokenDto)
async def refresh_token(
    dto: RefreshTokenDto, auth_service: AuthService = Depends(get_auth_service)
):
    """Access Token 갱신"""
    return await auth_service.refresh(dto)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(dto: RefreshTokenDto, auth_service: AuthService = Depends(get_auth_service)):
    """로그아웃 (현재 기기)"""
    await auth_service.logout(dto)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(user_id: str, auth_service: AuthService = Depends(get_auth_service)):
    """전체 로그아웃 (모든 기기)"""
    await auth_service.logout_all(user_id)
