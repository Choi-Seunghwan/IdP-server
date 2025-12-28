from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional
import bcrypt
import hashlib
from app.config import settings
from jose import JWTError, jwt

from app.core.exceptions import UnauthorizedException


def hash_password(password: str) -> str:
    """
    비밀번호 해시
    bcrypt는 72바이트 제한이 있으므로, 긴 비밀번호는 먼저 SHA-256으로 해시한 후 bcrypt에 전달
    """
    password_bytes = password.encode("utf-8")

    # 72바이트를 초과하는 경우 SHA-256으로 사전 해싱
    if len(password_bytes) > 72:
        password_bytes = hashlib.sha256(password_bytes).digest()

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    비밀번호를 검증 hash_password와 동일한 방식으로 처리
    """
    password_bytes = plain_password.encode("utf-8")

    # 72바이트를 초과하는 경우 SHA-256으로 사전 해싱
    if len(password_bytes) > 72:
        password_bytes = hashlib.sha256(password_bytes).digest()

    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token(data: Dict[str, Any]) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError:
        raise UnauthorizedException(detail="Could ont validate credentials")


def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
    payload = decode_token(token)
    if payload.get("type") != token_type:
        raise UnauthorizedException(detail="Invalid token type")
    return payload
