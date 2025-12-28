from app.core.redis import get_redis
from app.core.exceptions import BadRequestException
from typing import Optional

# State 만료 시간 (초) - 10분
STATE_EXPIRE_SECONDS = 600

"""OAuth State 관리 모듈. CSRF 공격 방지를 위한 state 검증"""


async def save_oauth_state(state: str, provider: str) -> None:
    """
    OAuth state를 Redis에 저장

    state: 생성된 state 값
    provider: OAuth provider (google, kakao, naver)
    """
    redis = await get_redis()
    key = f"oauth_state:{provider}:{state}"
    await redis.setex(key, STATE_EXPIRE_SECONDS, "1")


async def verify_oauth_state(state: str, provider: str) -> bool:
    """OAuth state를 검증하고 삭제 (일회용)"""
    redis = await get_redis()
    key = f"oauth_state:{provider}:{state}"

    # State 존재 확인 및 삭제
    exists = await redis.delete(key)

    if not exists:
        raise BadRequestException(
            detail="Invalid or expired state. This may be a CSRF attack attempt."
        )

    return True
