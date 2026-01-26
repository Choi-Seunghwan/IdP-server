import httpx
from app.config import settings
from app.social.dto import OAuthUserInfo
from app.core.exceptions import BadRequestException


class KakaoOAuthProvider:
    """Kakao OAuth 2.0 Provider"""

    AUTHORIZATION_URL = "https://kauth.kakao.com/oauth/authorize"
    TOKEN_URL = "https://kauth.kakao.com/oauth/token"
    USER_INFO_URL = "https://kapi.kakao.com/v2/user/me"

    @staticmethod
    def get_authorization_url(state: str) -> str:
        """Kakao OAuth 인증 URL 생성"""
        params = {
            "client_id": settings.kakao_client_id,
            "redirect_uri": settings.kakao_redirect_uri,
            "response_type": "code",
            "state": state,
        }
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{KakaoOAuthProvider.AUTHORIZATION_URL}?{query_string}"

    @staticmethod
    async def get_access_token(code: str) -> str:
        """Authorization code로 Access Token 획득"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                KakaoOAuthProvider.TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "client_id": settings.kakao_client_id,
                    "client_secret": settings.kakao_client_secret,
                    "code": code,
                    "redirect_uri": settings.kakao_redirect_uri,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if response.status_code != 200:
                raise BadRequestException(detail="Failed to get access token from Kakao")

            data = response.json()
            return data.get("access_token")

    @staticmethod
    async def get_user_info(access_token: str) -> OAuthUserInfo:
        """Access Token으로 사용자 정보 조회"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                KakaoOAuthProvider.USER_INFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )

            if response.status_code != 200:
                raise BadRequestException(detail="Failed to get user info from Kakao")

            data = response.json()
            kakao_account = data.get("kakao_account", {})
            profile = kakao_account.get("profile", {})

            return OAuthUserInfo(
                provider_user_id=str(data.get("id")),
                email=kakao_account.get("email"),
                name=profile.get("nickname"),
            )
