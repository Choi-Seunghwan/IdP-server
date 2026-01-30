from redis.asyncio import Redis
from app.config import settings
from typing import Optional


# Redis 클라이언트 인스턴스 (전역)
_redis_client: Optional[Redis] = None


async def get_redis() -> Redis:
    """Redis 클라이언트 반환 (싱글톤 패턴)"""
    global _redis_client
    if _redis_client is None:
        _redis_client = Redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_client


async def close_redis():
    """Redis 연결 종료"""
    global _redis_client
    if _redis_client:
        await _redis_client.aclose()
        _redis_client = None
