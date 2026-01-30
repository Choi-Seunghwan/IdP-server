import base64
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Optional

from jose import jwt

from app.auth.model import RefreshToken
from app.auth.persistence import RefreshTokenRepository, hash_token
from app.config import settings
from app.core.exceptions import BadRequestException, UnauthorizedException
from app.core.jwt_keys import get_jwk_from_public_key, load_rsa_public_key
from app.core.security import (
    JWT_ALGORITHM,
    _get_signing_key,
    create_access_token,
    create_refresh_token,
    verify_token,
)
from app.sso.client_service import ClientService
from app.sso.dto import TokenRequestDto, TokenResponseDto, UserInfoResponseDto
from app.sso.model import AuthorizationCode, OAuth2Client
from app.sso.persistence import AuthorizationCodeRepository
from app.user.service import UserService


class SSOService:
    """
    SSO (OAuth2/OIDC) 서비스
    OAuth2 Authorization Code Flow 처리
    """

    def __init__(
        self,
        client_service: ClientService,
        user_service: UserService,
        auth_code_repository: AuthorizationCodeRepository,
        refresh_token_repository: RefreshTokenRepository,
    ):
        self.client_service = client_service
        self.user_service = user_service
        self.auth_code_repository = auth_code_repository
        self.refresh_token_repository = refresh_token_repository

    async def create_authorization_code(
        self,
        client: OAuth2Client,
        user_id: str,
        redirect_uri: str,
        scopes: str,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ) -> str:
        """Authorization Code 생성 및 저장 (Redis)"""
        code = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(minutes=10)

        auth_code = AuthorizationCode(
            id=str(secrets.token_urlsafe(16)),
            code=code,
            client_id=client.client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=expires_at,
        )

        await self.auth_code_repository.create(auth_code)
        return code

    async def exchange_code_for_tokens(self, dto: TokenRequestDto) -> TokenResponseDto:
        """Authorization Code를 Access Token으로 교환"""
        if dto.grant_type != "authorization_code":
            raise BadRequestException(detail="grant_type must be 'authorization_code'")

        if not dto.code:
            raise BadRequestException(detail="code is required")

        client = await self.client_service.verify_client_secret(dto.client_id, dto.client_secret)

        auth_code = await self.auth_code_repository.find_by_code(dto.code)
        if not auth_code:
            raise UnauthorizedException(detail="Invalid authorization code")

        if auth_code.expires_at < datetime.now(UTC):
            raise UnauthorizedException(detail="Authorization code expired")

        if auth_code.is_used:
            raise UnauthorizedException(detail="Authorization code already used")

        if auth_code.client_id != dto.client_id:
            raise UnauthorizedException(detail="Client ID mismatch")

        if dto.redirect_uri and auth_code.redirect_uri != dto.redirect_uri:
            raise BadRequestException(detail="Redirect URI mismatch")

        # PKCE 검증
        if auth_code.code_challenge:
            if not dto.code_verifier:
                raise BadRequestException(detail="code_verifier is required for PKCE")

            if auth_code.code_challenge_method == "S256":
                challenge = (
                    base64.urlsafe_b64encode(hashlib.sha256(dto.code_verifier.encode()).digest())
                    .decode()
                    .rstrip("=")
                )
            else:
                challenge = dto.code_verifier

            if challenge != auth_code.code_challenge:
                raise UnauthorizedException(detail="Invalid code_verifier")

        user = await self.user_service.get_user_by_id(auth_code.user_id)

        # Access Token 생성
        access_token = create_access_token(
            data={
                "sub": user.id,
                "email": user.email,
                "client_id": client.client_id,
                "scope": auth_code.scopes,
            }
        )

        # Refresh Token 생성 및 DB 저장 (해시)
        refresh_token_value = create_refresh_token(
            data={"sub": user.id, "client_id": client.client_id, "scope": auth_code.scopes}
        )

        family_id = str(uuid.uuid4())
        refresh_token_entity = RefreshToken(
            id=str(uuid.uuid4()),
            token_hash=hash_token(refresh_token_value),
            user_id=user.id,
            family_id=family_id,
            rotated_from=None,
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
        )
        await self.refresh_token_repository.create(refresh_token_entity)

        # Authorization Code 사용 처리 (Redis에서 삭제)
        await self.auth_code_repository.mark_as_used(auth_code)

        # ID Token 생성
        id_token = self._create_id_token(user, client, auth_code.scopes)

        return TokenResponseDto(
            access_token=access_token,
            token_type="Bearer",
            expires_in=settings.access_token_expire_minutes * 60,
            refresh_token=refresh_token_value,
            scope=auth_code.scopes,
            id_token=id_token,
        )

    def _create_id_token(self, user, client: OAuth2Client, scopes: str) -> Optional[str]:
        """OpenID Connect ID Token 생성"""
        if "openid" not in scopes:
            return None

        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)

        payload = {
            "iss": settings.issuer,
            "sub": user.id,
            "aud": client.client_id,
            "exp": int(expires_at.timestamp()),
            "iat": int(now.timestamp()),
            "email": user.email,
            "email_verified": user.is_verified,
        }

        if "profile" in scopes and user.username:
            payload["name"] = user.username
            payload["preferred_username"] = user.username

        if "email" in scopes:
            payload["email"] = user.email

        signing_key = _get_signing_key()
        return jwt.encode(payload, signing_key, algorithm=JWT_ALGORITHM)

    async def get_user_info(self, access_token: str) -> UserInfoResponseDto:
        """OpenID Connect UserInfo 엔드포인트"""
        payload = verify_token(access_token, token_type="access")

        user_id = payload.get("sub")
        if not user_id:
            raise UnauthorizedException(detail="Invalid token")

        user = await self.user_service.get_user_by_id(user_id)

        return UserInfoResponseDto(
            sub=user.id,
            email=user.email,
            email_verified=user.is_verified,
            name=user.username,
            preferred_username=user.username,
            phone_number=user.phone_number,
            phone_number_verified=user.is_verified,
        )

    def get_jwks(self) -> dict:
        """JSON Web Key Set (JWKS) 제공 (RS256)"""
        public_key = load_rsa_public_key(settings.rsa_public_key_path)
        if not public_key:
            return {"keys": []}

        jwk_dict = get_jwk_from_public_key(public_key, kid="default")
        return {"keys": [jwk_dict]}

    async def refresh_tokens(
        self, client_id: str, client_secret: Optional[str], refresh_token: str
    ) -> TokenResponseDto:
        """Refresh Token으로 새 토큰 발급 (Token Rotation 적용)"""
        client = await self.client_service.verify_client_secret(client_id, client_secret)

        # JWT 서명 검증
        payload = verify_token(refresh_token, token_type="refresh")

        user_id = payload.get("sub")
        if not user_id:
            raise UnauthorizedException(detail="Invalid refresh token")

        token_client_id = payload.get("client_id")
        if token_client_id and token_client_id != client_id:
            raise UnauthorizedException(detail="Client ID mismatch")

        # DB에서 토큰 조회 (해시로)
        token_hash = hash_token(refresh_token)
        stored_token = await self.refresh_token_repository.find_by_token_hash(token_hash)

        if not stored_token:
            raise UnauthorizedException(detail="Invalid or revoked token")

        # 만료 확인
        expires_at = stored_token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at < datetime.now(UTC):
            raise UnauthorizedException(detail="Token expired")

        # Token Rotation: 기존 토큰 폐기
        await self.refresh_token_repository.revoke_by_id(stored_token.id)

        user = await self.user_service.get_user_by_id(user_id)
        scope = payload.get("scope", "openid profile email")

        # 새 Access Token
        access_token = create_access_token(
            data={
                "sub": user.id,
                "email": user.email,
                "client_id": client.client_id,
                "scope": scope,
            }
        )

        # 새 Refresh Token (같은 family)
        new_refresh_token = create_refresh_token(
            data={"sub": user.id, "client_id": client.client_id, "scope": scope}
        )

        new_refresh_token_entity = RefreshToken(
            id=str(uuid.uuid4()),
            token_hash=hash_token(new_refresh_token),
            user_id=user.id,
            family_id=stored_token.family_id,
            rotated_from=stored_token.id,
            expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_expire_days),
        )
        await self.refresh_token_repository.create(new_refresh_token_entity)

        id_token = self._create_id_token(user, client, scope)

        return TokenResponseDto(
            access_token=access_token,
            token_type="Bearer",
            expires_in=settings.access_token_expire_minutes * 60,
            refresh_token=new_refresh_token,
            scope=scope,
            id_token=id_token,
        )

    def get_openid_configuration(self) -> dict:
        """OpenID Connect Discovery 메타데이터"""
        base_url = settings.issuer.rstrip("/")

        return {
            "issuer": settings.issuer,
            "authorization_endpoint": f"{base_url}/oauth2/authorize",
            "token_endpoint": f"{base_url}/oauth2/token",
            "userinfo_endpoint": f"{base_url}/oauth2/userinfo",
            "jwks_uri": f"{base_url}/oauth2/jwks",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [JWT_ALGORITHM],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "claims_supported": [
                "sub",
                "email",
                "email_verified",
                "name",
                "preferred_username",
            ],
        }
