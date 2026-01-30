import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional

import bcrypt
from jose import JWTError, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.backends import default_backend

from app.config import settings
from app.core.exceptions import UnauthorizedException
from app.core.jwt_keys import (
    load_rsa_private_key,
    load_rsa_public_key,
    get_private_key_pem_string,
    get_public_key_pem_string,
)


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


def _get_signing_key():
    """JWT 서명에 사용할 키 반환 (알고리즘에 따라 다름)"""
    if settings.algorithm == "RS256":
        # RSA Private Key 로드
        private_key = None

        # 환경 변수에서 직접 키 로드 시도
        if settings.rsa_private_key:
            loaded_key = serialization.load_pem_private_key(
                settings.rsa_private_key.encode("utf-8"), password=None, backend=default_backend()
            )
            if not isinstance(loaded_key, RSAPrivateKey):
                raise ValueError("Only RSA private keys are supported")
            private_key = loaded_key
        else:
            # 파일에서 키 로드
            private_key = load_rsa_private_key(settings.rsa_private_key_path)

        if not private_key:
            raise ValueError(
                "RSA private key not found. "
                "Please set RSA_PRIVATE_KEY or RSA_PRIVATE_KEY_PATH in .env"
            )
        return get_private_key_pem_string(private_key)
    else:
        # HS256: 대칭키 사용
        return settings.secret_key


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({
        "exp": expire,
        "type": "access",
        "jti": str(uuid.uuid4()),
    })
    signing_key = _get_signing_key()
    return jwt.encode(to_encode, signing_key, algorithm=settings.algorithm)


def create_refresh_token(data: Dict[str, Any]) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({
        "exp": expire,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
    })
    signing_key = _get_signing_key()
    return jwt.encode(to_encode, signing_key, algorithm=settings.algorithm)


def _get_verification_key():
    """JWT 검증에 사용할 키 반환 (알고리즘에 따라 다름)"""
    if settings.algorithm == "RS256":
        # RSA Public Key 로드
        public_key = None

        # 환경 변수에서 직접 키 로드 시도
        if settings.rsa_public_key:
            loaded_key = serialization.load_pem_public_key(
                settings.rsa_public_key.encode("utf-8"), backend=default_backend()
            )
            if not isinstance(loaded_key, RSAPublicKey):
                raise ValueError("Only RSA public keys are supported")
            public_key = loaded_key
        else:
            # 파일에서 키 로드
            public_key = load_rsa_public_key(settings.rsa_public_key_path)

        if not public_key:
            raise ValueError(
                "RSA public key not found. "
                "Please set RSA_PUBLIC_KEY or RSA_PUBLIC_KEY_PATH in .env"
            )
        # jose 라이브러리는 PEM 문자열을 기대하므로 변환
        return get_public_key_pem_string(public_key)
    else:
        # HS256: 대칭키 사용
        return settings.secret_key


def decode_token(token: str) -> Dict[str, Any]:
    try:
        verification_key = _get_verification_key()
        return jwt.decode(token, verification_key, algorithms=[settings.algorithm])
    except JWTError:
        raise UnauthorizedException(detail="Could not validate credentials")


def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
    payload = decode_token(token)
    if payload.get("type") != token_type:
        raise UnauthorizedException(detail="Invalid token type")
    return payload
