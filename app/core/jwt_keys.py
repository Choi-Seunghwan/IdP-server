"""
JWT 키 관리 모듈
RSA 키 쌍 생성 및 로드
"""

import os
import base64
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_key_pair() -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """RSA 키 쌍 생성 (2048비트)"""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_rsa_key_pair(
    private_key: RSAPrivateKey,
    public_key: RSAPublicKey,
    private_key_path: str,
    public_key_path: str,
) -> None:
    """RSA 키 쌍을 파일로 저장"""
    # Private Key 저장 (PEM 형식)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    Path(private_key_path).parent.mkdir(parents=True, exist_ok=True)
    with open(private_key_path, "wb") as f:
        f.write(private_pem)

    # Public Key 저장 (PEM 형식)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    Path(public_key_path).parent.mkdir(parents=True, exist_ok=True)
    with open(public_key_path, "wb") as f:
        f.write(public_pem)


def load_rsa_private_key(key_path: str) -> Optional[RSAPrivateKey]:
    """RSA Private Key 로드"""
    if not os.path.exists(key_path):
        return None

    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    # RSA 키만 지원
    if not isinstance(private_key, RSAPrivateKey):
        return None
    return private_key


def load_rsa_public_key(key_path: str) -> Optional[RSAPublicKey]:
    """RSA Public Key 로드"""
    if not os.path.exists(key_path):
        return None

    with open(key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    # RSA 키만 지원
    if not isinstance(public_key, RSAPublicKey):
        return None
    return public_key


def get_jwk_from_public_key(public_key: RSAPublicKey, kid: str = "default") -> dict:
    """
    RSA Public Key를 JWK 형식으로 변환

    Args:
        public_key: RSA Public Key
        kid: Key ID

    Returns:
        JWK 딕셔너리
    """
    # JWK 형식으로 변환
    public_numbers = public_key.public_numbers()

    # Base64 URL 인코딩 (패딩 제거)
    def base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    # n (modulus)와 e (exponent)를 Base64 URL 인코딩
    n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": base64url_encode(n_bytes),
        "e": base64url_encode(e_bytes),
    }


def get_private_key_pem_string(private_key: RSAPrivateKey) -> str:
    """Private Key를 PEM 문자열로 변환"""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


def get_public_key_pem_string(public_key: RSAPublicKey) -> str:
    """Public Key를 PEM 문자열로 변환"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode("utf-8")
