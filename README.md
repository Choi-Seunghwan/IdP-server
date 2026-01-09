# IdP Server

사내 서비스들을 위한 SSO 인증 서버. OAuth2/OIDC 표준을 따르는 IdP 서버입니다.

## 기능

- 이메일 회원가입/로그인 (JWT, RS256/HS256 지원)
- 소셜 로그인 (Google, Kakao, Naver)
- SSO (OAuth2 Authorization Code Flow, PKCE 지원)
- OIDC (ID Token, UserInfo, JWKS, Discovery)
- MSA 환경 지원 (RS256 + JWKS)

## 기술 스택

FastAPI, PostgreSQL (async), SQLAlchemy 2.0, Redis, uv

## 구조

```
app/
├── core/      # DB, Security, Exceptions
├── user/      # 회원
├── auth/      # 인증
├── social/    # 소셜 로그인
└── sso/       # OAuth2/OIDC
```

DDD + Clean Architecture 패턴 사용. 각 도메인은 model, dto, persistence, service, api로 구성.

## 실행

```bash
# 1. .env 파일 설정
cp .env.example .env
# DATABASE_URL, SECRET_KEY 등 수정

# 2. 의존성 설치
uv sync

# 3. RSA 키 생성 (RS256 사용 시)
uv run python scripts/generate_rsa_keys.py
# .env에 ALGORITHM=RS256 설정

# 4. DB 마이그레이션
uv run alembic upgrade head

# 5. 서버 실행
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API 문서: http://localhost:8000/docs

## API

### 인증
- `POST /api/auth/login` - 로그인
- `POST /api/auth/refresh` - 토큰 갱신
- `POST /api/auth/logout` - 로그아웃

### 사용자
- `POST /api/users` - 회원가입
- `GET /api/users/me` - 프로필 조회
- `PATCH /api/users/me` - 프로필 수정

### 소셜 로그인
- `GET /api/social/{provider}/login` - 소셜 로그인 URL
- `GET /api/social/{provider}/callback` - OAuth 콜백

### SSO (OAuth2/OIDC)
- `POST /api/oauth2/clients` - Client 등록
- `GET /api/oauth2/login` - IdP 로그인 페이지
- `GET /api/oauth2/authorize` - Authorization 요청
- `POST /api/oauth2/token` - Token 교환
- `GET /api/oauth2/userinfo` - 사용자 정보
- `GET /api/oauth2/jwks` - 공개키 (MSA용)
- `GET /api/oauth2/.well-known/openid-configuration` - OIDC 메타데이터

## SSO 사용법

### 1. Client 등록

```bash
POST /api/oauth2/clients
{
  "name": "내부 관리 시스템",
  "client_type": "public",
  "redirect_uri": "http://localhost:3000/callback",
  "scopes": "openid profile email"
}
```

### 2. Authorization Code Flow

1. 사용자를 `/api/oauth2/authorize?client_id=xxx&redirect_uri=xxx`로 리다이렉트
2. 로그인 안 되어 있으면 IdP 로그인 페이지로 이동
3. 로그인 후 Authorization Code 받음
4. Code를 `/api/oauth2/token`으로 교환하여 Access Token 획득
5. Access Token으로 `/api/oauth2/userinfo`에서 사용자 정보 조회

### MSA 토큰 검증

다른 서비스에서 토큰 검증:
1. `GET /api/oauth2/jwks`에서 공개키 가져오기
2. 공개키로 JWT 검증

