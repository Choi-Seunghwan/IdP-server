from fastapi import Depends
from app.core.dependencies import get_current_user_id_from_token
from app.user.service import UserService
from app.user.di import get_user_service
from app.user.dto import UserDto


async def get_current_user(
    user_id: str = Depends(get_current_user_id_from_token),
    user_service: UserService = Depends(get_user_service),
) -> UserDto:
    """현재 로그인한 사용자 정보 조회"""
    return await user_service.get_user_by_id(user_id)
