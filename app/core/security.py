import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional

import bcrypt
from jose import JWTError, jwt

from app.config import settings
from app.core.exceptions import UnauthorizedException
from app.core.jwt_keys import (
    load_rsa_private_key,
    load_rsa_public_key,
    get_private_key_pem_string,
    get_public_key_pem_string,
)

# JWT 알고리즘 (RS256 고정, MSA 환경에서 비대칭키 사용)
JWT_ALGORITHM = "RS256"


def hash_password(password: str) -> str:
    """
    비밀번호 해시 (SHA-256 + bcrypt)
    bcrypt는 72바이트 제한이 있음. 비밀번호 SHA-256으로 해싱
    """
    # SHA-256 사전 해싱 (32바이트 출력, bcrypt 72바이트 제한 내)
    password_bytes = hashlib.sha256(password.encode("utf-8")).digest()

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    비밀번호 검증 (SHA-256 + bcrypt)
    hash_password와 동일한 방식으로 처리
    """
    # SHA-256 사전 해싱
    password_bytes = hashlib.sha256(plain_password.encode("utf-8")).digest()

    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def _get_signing_key() -> str:
    """JWT 서명에 사용할 RSA Private Key 반환 (파일에서 로드)"""
    private_key = load_rsa_private_key(settings.rsa_private_key_path)
    if not private_key:
        raise ValueError(
            f"RSA private key not found at {settings.rsa_private_key_path}"
        )
    return get_private_key_pem_string(private_key)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update(
        {
            "exp": expire,
            "type": "access",
            "jti": str(uuid.uuid4()),
        }
    )
    signing_key = _get_signing_key()
    return jwt.encode(to_encode, signing_key, algorithm=JWT_ALGORITHM)


def create_refresh_token(data: Dict[str, Any]) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update(
        {
            "exp": expire,
            "type": "refresh",
            "jti": str(uuid.uuid4()),
        }
    )
    signing_key = _get_signing_key()
    return jwt.encode(to_encode, signing_key, algorithm=JWT_ALGORITHM)


def _get_verification_key() -> str:
    """JWT 검증에 사용할 RSA Public Key 반환 (파일에서 로드)"""
    public_key = load_rsa_public_key(settings.rsa_public_key_path)
    if not public_key:
        raise ValueError(
            f"RSA public key not found at {settings.rsa_public_key_path}"
        )
    return get_public_key_pem_string(public_key)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        verification_key = _get_verification_key()
        return jwt.decode(token, verification_key, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise UnauthorizedException(detail="Could not validate credentials")


def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
    payload = decode_token(token)
    if payload.get("type") != token_type:
        raise UnauthorizedException(detail="Invalid token type")
    return payload
