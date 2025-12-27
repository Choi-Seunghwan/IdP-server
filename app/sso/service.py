import secrets
import hashlib
import base64
from datetime import datetime, timedelta, UTC
from typing import Optional
from app.sso.model import AuthorizationCode, OAuth2Client
from app.sso.dto import TokenRequestDto, TokenResponseDto, UserInfoResponseDto
from app.sso.persistence import (
    OAuth2ClientRepository,
    AuthorizationCodeRepository,
)
from app.sso.client_service import ClientService
from app.user.service import UserService
from app.core.security import create_access_token, create_refresh_token, verify_token
from app.core.exceptions import (
    BadRequestException,
    UnauthorizedException,
    NotFoundException,
)
from app.config import settings


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
    ):
        self.client_service = client_service
        self.user_service = user_service
        self.auth_code_repository = auth_code_repository

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
        """
        Authorization Code 생성 및 저장
        """
        # Authorization Code 생성 (랜덤 문자열)
        code = secrets.token_urlsafe(32)

        # 만료 시간 (10분)
        expires_at = datetime.now(UTC) + timedelta(minutes=10)

        # Authorization Code 엔티티 생성
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

        # 저장
        await self.auth_code_repository.create(auth_code)

        return code

    async def exchange_code_for_tokens(
        self, dto: TokenRequestDto
    ) -> TokenResponseDto:
        """
        Authorization Code를 Access Token으로 교환
        OAuth2 표준: POST /oauth2/token
        """
        if dto.grant_type != "authorization_code":
            raise BadRequestException(detail="grant_type must be 'authorization_code'")

        if not dto.code:
            raise BadRequestException(detail="code is required")

        # Client 검증
        client = await self.client_service.verify_client_secret(
            dto.client_id, dto.client_secret
        )

        # Authorization Code 조회
        auth_code = await self.auth_code_repository.find_by_code(dto.code)
        if not auth_code:
            raise UnauthorizedException(detail="Invalid authorization code")

        # 만료 확인
        if auth_code.expires_at < datetime.now(UTC):
            raise UnauthorizedException(detail="Authorization code expired")

        # 사용 여부 확인
        if auth_code.is_used:
            raise UnauthorizedException(detail="Authorization code already used")

        # Client ID 일치 확인
        if auth_code.client_id != dto.client_id:
            raise UnauthorizedException(detail="Client ID mismatch")

        # Redirect URI 검증
        if dto.redirect_uri and auth_code.redirect_uri != dto.redirect_uri:
            raise BadRequestException(detail="Redirect URI mismatch")

        # PKCE 검증 (있는 경우)
        if auth_code.code_challenge:
            if not dto.code_verifier:
                raise BadRequestException(detail="code_verifier is required for PKCE")

            # code_verifier로 code_challenge 재계산
            if auth_code.code_challenge_method == "S256":
                # SHA256 해시
                challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(dto.code_verifier.encode()).digest()
                ).decode().rstrip("=")
            else:  # plain
                challenge = dto.code_verifier

            if challenge != auth_code.code_challenge:
                raise UnauthorizedException(detail="Invalid code_verifier")

        # 사용자 조회
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

        # Refresh Token 생성
        refresh_token_value = create_refresh_token(
            data={"sub": user.id, "client_id": client.client_id}
        )

        # Authorization Code 사용 처리
        await self.auth_code_repository.mark_as_used(auth_code)

        # ID Token 생성 (OpenID Connect)
        id_token = self._create_id_token(user, client, auth_code.scopes)

        return TokenResponseDto(
            access_token=access_token,
            token_type="Bearer",
            expires_in=settings.access_token_expire_minutes * 60,
            refresh_token=refresh_token_value,
            scope=auth_code.scopes,
            id_token=id_token,
        )

    def _create_id_token(
        self, user, client: OAuth2Client, scopes: str
    ) -> Optional[str]:
        """
        OpenID Connect ID Token 생성
        """
        # openid 스코프가 없으면 ID Token 발급 안 함
        if "openid" not in scopes:
            return None

        from jose import jwt

        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)

        # ID Token 페이로드 (OIDC 표준)
        payload = {
            "iss": settings.issuer,  # Issuer (발급자 URL)
            "sub": user.id,  # Subject (사용자 ID)
            "aud": client.client_id,  # Audience (Client ID)
            "exp": int(expires_at.timestamp()),  # Expiration
            "iat": int(now.timestamp()),  # Issued At
            "email": user.email,
            "email_verified": user.is_verified,
        }

        # name 스코프가 있으면 추가
        if "profile" in scopes and user.username:
            payload["name"] = user.username
            payload["preferred_username"] = user.username

        # email 스코프가 있으면 추가
        if "email" in scopes:
            payload["email"] = user.email

        # ID Token 서명
        return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)

    async def get_user_info(self, access_token: str) -> UserInfoResponseDto:
        """
        OpenID Connect UserInfo 엔드포인트
        GET /oauth2/userinfo
        """
        # Access Token 검증
        payload = verify_token(access_token, token_type="access")

        user_id = payload.get("sub")
        if not user_id:
            raise UnauthorizedException(detail="Invalid token")

        # 사용자 조회
        user = await self.user_service.get_user_by_id(user_id)

        # UserInfo 응답 생성
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
        """
        JSON Web Key Set (JWKS) 제공
        GET /oauth2/jwks
        JWT 검증을 위한 공개키 제공
        """
        # HS256은 대칭키이므로 공개키가 없음
        # 실제 운영 환경에서는 RS256 (비대칭키) 사용 권장
        # 여기서는 간단한 예시만 제공
        
        # HS256의 경우, 공개키가 없으므로 빈 키셋 반환
        # 또는 secret_key를 기반으로 한 키 정보 제공 (보안상 권장하지 않음)
        return {
            "keys": [
                {
                    "kty": "oct",  # Octet sequence (대칭키)
                    "alg": settings.algorithm,
                    "use": "sig",  # signature
                    # 실제로는 공개키를 제공해야 하지만, HS256은 대칭키이므로
                    # 클라이언트는 secret_key를 알고 있어야 함
                    # 운영 환경에서는 RS256 사용 권장
                }
            ]
        }

    def get_openid_configuration(self) -> dict:
        """
        OpenID Connect Discovery 메타데이터
        GET /.well-known/openid-configuration
        """
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
            "id_token_signing_alg_values_supported": [settings.algorithm],
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

