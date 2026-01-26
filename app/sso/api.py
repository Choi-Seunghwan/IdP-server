from urllib.parse import urlencode, quote

from fastapi import APIRouter, Depends, Query, Form, Header, status
from fastapi.responses import RedirectResponse, HTMLResponse
from pathlib import Path
from typing import Optional

from app.sso.dto import (
    CreateClientDto,
    ClientDto,
    TokenRequestDto,
    TokenResponseDto,
    UserInfoResponseDto,
)
from app.sso.service import SSOService
from app.sso.client_service import ClientService
from app.sso.di import get_sso_service, get_client_service
from app.core.dependencies import get_optional_user_id_from_token
from app.core.exceptions import BadRequestException


router = APIRouter(prefix="/oauth2", tags=["sso"])


# Client 관리 엔드포인트 (관리자용)
@router.post("/clients", response_model=ClientDto, status_code=status.HTTP_201_CREATED)
async def create_client(
    dto: CreateClientDto,
    client_service: ClientService = Depends(get_client_service),
):
    """
    OAuth2 Client 등록
    사내 서비스를 Client로 등록하여 SSO 사용 가능하게 함
    """
    return await client_service.create_client(dto)


@router.get("/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: Optional[str] = Query("openid profile email"),
    state: Optional[str] = Query(None),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: Optional[str] = Query(None),
    sso_service: SSOService = Depends(get_sso_service),
    client_service: ClientService = Depends(get_client_service),
    current_user_id: Optional[str] = Depends(get_optional_user_id_from_token),
):
    """
    OAuth2 Authorization 엔드포인트
    GET /oauth2/authorize?response_type=code&client_id=xxx&redirect_uri=xxx&scope=xxx&state=xxx

    플로우:
    1. 사용자가 로그인하지 않았으면 → 로그인 페이지로 리다이렉트
    2. 사용자가 로그인했으면 → Authorization Code 생성 후 redirect_uri로 리다이렉트
    """
    # response_type 검증
    if response_type != "code":
        raise BadRequestException(
            detail="response_type must be 'code' (Authorization Code Flow only)"
        )

    # Client 조회 및 검증
    client = await client_service.get_client_by_client_id(client_id)

    # Redirect URI 검증 (여러 개의 redirect_uri 지원)
    allowed_uris = [uri.strip() for uri in client.redirect_uri.split(",")]
    if redirect_uri not in allowed_uris:
        raise BadRequestException(detail="Invalid redirect_uri")

    # 사용자 인증 확인
    if not current_user_id:
        # 로그인하지 않았으면 로그인 페이지로 리다이렉트
        # authorize 파라미터들을 URL 인코딩하여 전달
        authorize_params = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
        }
        if state:
            authorize_params["state"] = state
        if code_challenge:
            authorize_params["code_challenge"] = code_challenge
        if code_challenge_method:
            authorize_params["code_challenge_method"] = code_challenge_method

        # authorize URL 생성 (한 번만 인코딩)
        authorize_url = f"/api/oauth2/authorize?{urlencode(authorize_params)}"
        # redirect 파라미터로 전달 (quote로 한 번만 인코딩)
        login_url = f"/api/oauth2/login?redirect={quote(authorize_url, safe='')}"
        return RedirectResponse(url=login_url)

    # Authorization Code 생성
    auth_code = await sso_service.create_authorization_code(
        client=client,
        user_id=current_user_id,
        redirect_uri=redirect_uri,
        scopes=scope or "openid profile email",
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    # redirect_uri로 리다이렉트 (Authorization Code 포함)
    redirect_url = f"{redirect_uri}?code={auth_code}"
    if state:
        redirect_url += f"&state={state}"

    return RedirectResponse(url=redirect_url)


@router.post("/token", response_model=TokenResponseDto)
async def token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    sso_service: SSOService = Depends(get_sso_service),
):
    """
    OAuth2 Token 엔드포인트
    POST /oauth2/token

    Authorization Code를 Access Token으로 교환
    또는 Refresh Token으로 새 Access Token 발급
    """
    # Form 데이터를 DTO로 변환
    if grant_type == "authorization_code":
        dto = TokenRequestDto(
            grant_type=grant_type,
            code=code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=None,
            code_verifier=code_verifier,
        )
        return await sso_service.exchange_code_for_tokens(dto)

    elif grant_type == "refresh_token":
        if not refresh_token:
            raise BadRequestException(detail="refresh_token is required")
        return await sso_service.refresh_tokens(
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
        )

    else:
        raise BadRequestException(detail=f"Unsupported grant_type: {grant_type}")


@router.get("/userinfo", response_model=UserInfoResponseDto)
async def userinfo(
    authorization: Optional[str] = Header(None),
    sso_service: SSOService = Depends(get_sso_service),
):
    """
    OpenID Connect UserInfo 엔드포인트
    GET /oauth2/userinfo

    Authorization: Bearer <access_token> 헤더 필요
    """
    # Authorization 헤더에서 토큰 추출
    if not authorization:
        raise BadRequestException(detail="Authorization header required")

    if not authorization.startswith("Bearer "):
        raise BadRequestException(detail="Invalid authorization header format")

    access_token = authorization.replace("Bearer ", "")

    return await sso_service.get_user_info(access_token)


@router.get("/jwks")
async def jwks(sso_service: SSOService = Depends(get_sso_service)):
    """
    JSON Web Key Set (JWKS) 엔드포인트
    GET /oauth2/jwks

    JWT 검증을 위한 공개키 제공
    """
    return sso_service.get_jwks()


@router.get("/.well-known/openid-configuration")
async def openid_configuration(sso_service: SSOService = Depends(get_sso_service)):
    """
    OpenID Connect Discovery 엔드포인트
    GET /.well-known/openid-configuration

    OIDC 메타데이터 제공
    """
    return sso_service.get_openid_configuration()


# ============================================
# IDP 로그인 페이지
# ============================================


@router.get("/login")
async def login_page(redirect: Optional[str] = Query(None)):
    """
    IDP 로그인 페이지
    GET /oauth2/login?redirect=xxx

    SSO 로그인 시 사용되는 로그인 페이지
    로그인 성공 후 redirect 파라미터로 지정된 경로로 리다이렉트
    """
    # HTML 파일 읽기
    templates_dir = Path(__file__).parent / "templates"
    html_file = templates_dir / "login.html"
    html_content = html_file.read_text(encoding="utf-8")

    return HTMLResponse(content=html_content)


@router.get("/social-callback")
async def social_callback(
    access_token: str = Query(...),
    refresh_token: str = Query(...),
    redirect: str = Query(...),
):
    """
    소셜 로그인 콜백 처리 페이지
    GET /oauth2/social-callback?access_token=xxx&refresh_token=xxx&redirect=xxx

    소셜 로그인 후 토큰을 받아서 저장하고 원래 URL로 리다이렉트
    """
    # HTML 페이지로 토큰 저장 및 리다이렉트
    html_content = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>로그인 처리 중...</title>
    </head>
    <body>
        <script>
            // 토큰 저장
            localStorage.setItem("access_token", "{access_token}");
            localStorage.setItem("refresh_token", "{refresh_token}");
            
            // 쿠키에도 토큰 저장
            const expires = new Date();
            expires.setTime(expires.getTime() + 30 * 60 * 1000); // 30분
            document.cookie = `access_token={access_token}; expires=${{expires.toUTCString()}}; path=/; SameSite=Lax`;
            
            // 원래 URL로 리다이렉트
            window.location.href = "{redirect}";
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
