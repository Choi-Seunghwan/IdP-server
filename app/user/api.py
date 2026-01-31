from fastapi import APIRouter, Depends, status
from app.user.di import get_user_service
from app.user.dto import ChangePasswordDto, CreateUserDto, UpdateUserDto, UserDto
from app.user.service import UserService
from app.core.dependencies import get_current_user_id_from_token
from app.user.dependencies import get_current_user


router = APIRouter(prefix="/users", tags=["users"])


@router.post("", response_model=UserDto, status_code=status.HTTP_201_CREATED)
async def create_user(dto: CreateUserDto, user_service: UserService = Depends(get_user_service)):
    """회원가입"""
    return await user_service.create_user(dto)


@router.get("/me", response_model=UserDto)
async def get_my_profile(current_user: UserDto = Depends(get_current_user)):
    """내 프로필 조회"""
    return current_user


@router.patch("/me", response_model=UserDto)
async def update_my_profile(
    dto: UpdateUserDto,
    current_user_id: str = Depends(get_current_user_id_from_token),
    user_service: UserService = Depends(get_user_service),
):
    """내 프로필 수정"""
    return await user_service.update_user(current_user_id, dto)


@router.post("/me/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_my_password(
    dto: ChangePasswordDto,
    current_user_id: str = Depends(get_current_user_id_from_token),
    user_service: UserService = Depends(get_user_service),
):
    """비밀번호 변경"""
    await user_service.change_password(current_user_id, dto)


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_my_account(
    current_user_id: str = Depends(get_current_user_id_from_token),
    user_service: UserService = Depends(get_user_service),
):
    """회원 탈퇴"""
    await user_service.delete_user(current_user_id)
