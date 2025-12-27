import httpx
from app.config import settings
from app.core.exceptions import BadRequestException
from app.social.dto import OAuthUserInfo


class GoogleOAuthProvider:
    """Google OAuth Provider"""

    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USER_INFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

    @staticmethod
    def get_authorization_url(state: str) -> str:
        """Google OAuth 인증 URL 생성"""

        params = {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
        }

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])

        return f"{GoogleOAuthProvider.AUTHORIZATION_URL}?{query_string}"

    @staticmethod
    async def get_access_token(code: str) -> str:
        """Authorization code로 Access Token 가져오기"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                GoogleOAuthProvider.TOKEN_URL,
                data={
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": settings.google_redirect_uri,
                },
            )

            if response.status_code != 200:
                raise BadRequestException(detail="failed to get access token")

            data = response.json()
            return data.get("access_token")

    @staticmethod
    async def get_user_info(access_token: str) -> OAuthUserInfo:
        """Access Token으로 사용자 정보 조회"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                GoogleOAuthProvider.USER_INFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if response.status_code != 200:
                raise BadRequestException(detail="failed to get user info")

            data = response.json()
            return OAuthUserInfo(
                provider_user_id=data.get("id", email=data.get("email"), name=data.get("name"))
            )
