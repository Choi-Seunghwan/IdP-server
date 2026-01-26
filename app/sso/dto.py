from pydantic import BaseModel, Field
from typing import Optional
from app.sso.model import ClientType


# Client 관리용 DTO
class CreateClientDto(BaseModel):
    """OAuth2 Client 등록 요청"""

    name: str = Field(..., description="서비스 이름")
    description: Optional[str] = Field(None, description="서비스 설명")
    client_type: ClientType = Field(ClientType.CONFIDENTIAL, description="Client 타입")
    redirect_uri: str = Field(..., description="리다이렉트 URI")
    scopes: str = Field("openid profile email", description="요청할 수 있는 스코프")


class ClientDto(BaseModel):
    """OAuth2 Client 응답"""

    id: str
    client_id: str
    name: str
    description: Optional[str]
    client_type: ClientType
    redirect_uri: str
    scopes: str
    is_active: bool
    created_at: str

    class Config:
        from_attributes = True


# OAuth2 표준 요청/응답 DTO
class AuthorizeRequestDto(BaseModel):
    """
    OAuth2 Authorization 요청
    GET /oauth2/authorize?response_type=code&client_id=xxx&redirect_uri=xxx&scope=xxx&state=xxx
    """

    response_type: str = Field(..., description="반드시 'code'")
    client_id: str = Field(..., description="Client ID")
    redirect_uri: str = Field(..., description="리다이렉트 URI")
    scope: Optional[str] = Field("openid profile email", description="요청 스코프")
    state: Optional[str] = Field(None, description="CSRF 방지용 state")
    code_challenge: Optional[str] = Field(None, description="PKCE code challenge")
    code_challenge_method: Optional[str] = Field(None, description="PKCE method (S256 or plain)")


class TokenRequestDto(BaseModel):
    """
    OAuth2 Token 요청
    POST /oauth2/token
    """

    grant_type: str = Field(..., description="'authorization_code' or 'refresh_token'")
    code: Optional[str] = Field(
        None, description="Authorization Code (grant_type=authorization_code일 때)"
    )
    redirect_uri: Optional[str] = Field(None, description="리다이렉트 URI (검증용)")
    client_id: str = Field(..., description="Client ID")
    client_secret: Optional[str] = Field(
        None, description="Client Secret (Confidential 클라이언트만)"
    )
    refresh_token: Optional[str] = Field(
        None, description="Refresh Token (grant_type=refresh_token일 때)"
    )
    code_verifier: Optional[str] = Field(None, description="PKCE code verifier")


class TokenResponseDto(BaseModel):
    """
    OAuth2 Token 응답 (표준 형식)
    """

    access_token: str
    token_type: str = "Bearer"
    expires_in: int = Field(..., description="만료 시간 (초)")
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = Field(None, description="OpenID Connect ID Token")


class UserInfoResponseDto(BaseModel):
    """
    OpenID Connect UserInfo 응답
    GET /oauth2/userinfo
    """

    sub: str = Field(..., description="사용자 ID (subject)")
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    name: Optional[str] = None
    preferred_username: Optional[str] = None
    phone_number: Optional[str] = None
    phone_number_verified: Optional[bool] = None
