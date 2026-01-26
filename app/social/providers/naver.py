import httpx
from app.config import settings
from app.social.dto import OAuthUserInfo
from app.core.exceptions import BadRequestException


class NaverOAuthProvider:
    """Naver OAuth Provider"""

    AUTHORIZATION_URL = "https://nid.naver.com/oauth2.0/authorize"
    TOKEN_URL = "https://nid.naver.com/oauth2.0/token"
    USER_INFO_URL = "https://openapi.naver.com/v1/nid/me"

    @staticmethod
    def get_authorization_url(state: str) -> str:
        """Naver OAuth 인증 URL 생성"""
        params = {
            "client_id": settings.naver_client_id,
            "redirect_uri": settings.naver_redirect_uri,
            "response_type": "code",
            "state": state,
        }
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])

        return f"{NaverOAuthProvider.AUTHORIZATION_URL}?{query_string}"

    @staticmethod
    async def get_access_token(code: str) -> str:
        """Authorization code로 Access Token 획득"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                NaverOAuthProvider.TOKEN_URL,
                params={
                    "grant_type": "authorization_code",
                    "client_id": settings.naver_client_id,
                    "client_secret": settings.naver_client_secret,
                    "code": code,
                },
            )

            if response.status_code != 200:
                raise BadRequestException(detail="Failed to get access token from Naver")

            data = response.json()
            return data.get("access_token")

    @staticmethod
    async def get_user_info(access_token: str) -> OAuthUserInfo:
        """Access Token으로 사용자 정보 조회"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                NaverOAuthProvider.USER_INFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if response.status_code != 200:
                raise BadRequestException(detail="Failed to get user info from Naver")

            data = response.json()
            user_data = data.get("response", {})

            return OAuthUserInfo(
                provider_user_id=user_data.get("id"),
                email=user_data.get("email"),
                name=user_data.get("name") or user_data.get("nickname"),
            )
