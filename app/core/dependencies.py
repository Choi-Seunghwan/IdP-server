from typing import Optional
from fastapi import Header
from app.core.exceptions import UnauthorizedException
from app.core.security import verify_token


async def get_token_from_header(
    authorization: Optional[str] = Header(None)
) -> str:
    """Authorization 헤더에서 토큰 추출"""
    if not authorization:
        raise UnauthorizedException(detail="Authorization header missing")

    # "Bearer <token>" 형식
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedException(detail="Invalid authorization header format")

    return parts[1]


async def get_current_user_id_from_token(
    authorization: Optional[str] = Header(None)
) -> str:
    """JWT에서 사용자 ID 추출"""
    token = await get_token_from_header(authorization)

    # JWT 검증 및 사용자 ID 추출
    payload = verify_token(token, token_type="access")
    user_id = payload.get("sub")

    if not user_id:
        raise UnauthorizedException(detail="Invalid token payload")

    return user_id


async def get_optional_token_from_header(
    authorization: Optional[str] = Header(None)
) -> Optional[str]:
    """선택적 토큰 추출 (없어도 OK)"""
    if not authorization:
        return None

    try:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
    except Exception:
        pass

    return None


async def get_optional_user_id_from_token(
    authorization: Optional[str] = Header(None)
) -> Optional[str]:
    """선택적 사용자 ID 추출 (토큰이 없어도 OK)"""
    token = await get_optional_token_from_header(authorization)
    if not token:
        return None

    try:
        payload = verify_token(token, token_type="access")
        return payload.get("sub")
    except Exception:
        return None
