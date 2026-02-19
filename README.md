# IdP Server

OAuth2/OIDC 표준을 따르는 Identity Provider 서버.
사내 서비스들의 인증을 중앙화하고 SSO를 제공합니다.

## 기능

- 이메일 회원가입 / 로그인
- 소셜 로그인 (Google, Kakao, Naver)
- SSO (OAuth2 Authorization Code Flow, PKCE 지원)
- OIDC (ID Token, UserInfo, JWKS, Discovery)
- Token Rotation + Reuse Detection
- RS256 비대칭키 JWT (MSA 환경 지원)

## 기술 스택

| 구분 | 기술 |
|------|------|
| Framework | FastAPI (Python 3.11+) |
| Database | PostgreSQL + SQLAlchemy 2.0 (async) |
| Cache | Redis |
| JWT | RS256 (비대칭키) |
| Package Manager | uv |

## 구조

DDD + Clean Architecture 패턴. 각 도메인은 `api`, `service`, `persistence`, `model`, `dto`, `di`로 구성.

```
app/
├── core/      # DB, Redis, Security, JWT 키 관리, 예외
├── user/      # 사용자 계정
├── auth/      # 인증, Access/Refresh Token
├── social/    # 소셜 로그인 (Google, Kakao, Naver)
└── sso/       # OAuth2 / OIDC 엔드포인트
```

## 실행

```bash
# 1. 환경변수 설정
cp .env.example .env

# 2. 의존성 설치
uv sync

# 3. RSA 키 생성
uv run python scripts/generate_rsa_keys.py

# 4. DB 마이그레이션
uv run alembic upgrade head

# 5. 서버 실행
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API 문서: http://localhost:8000/docs

## API

### 사용자
- `POST /api/users` - 회원가입
- `GET /api/users/me` - 프로필 조회
- `PATCH /api/users/me` - 프로필 수정

### 인증
- `POST /api/auth/login` - 로그인
- `POST /api/auth/refresh` - 토큰 갱신 (Token Rotation)
- `POST /api/auth/logout` - 로그아웃
- `POST /api/auth/logout-all` - 전체 기기 로그아웃

### 소셜 로그인
- `GET /api/social/{provider}/login` - 소셜 로그인 URL 생성
- `GET /api/social/{provider}/callback` - OAuth 콜백 처리
- `POST /api/social/connect` - 소셜 계정 연결
- `GET /api/social/accounts` - 연결된 소셜 계정 목록
- `DELETE /api/social/accounts/{id}` - 소셜 계정 연결 해제

### SSO (OAuth2 / OIDC)
- `GET /api/oauth2/login` - IdP 로그인 페이지
- `GET /api/oauth2/authorize` - Authorization Code 발급
- `POST /api/oauth2/token` - Token 교환 (authorization_code, refresh_token)
- `GET /api/oauth2/userinfo` - 사용자 정보 (OIDC)
- `GET /api/oauth2/jwks` - 공개키 (MSA 토큰 검증용)
- `GET /api/oauth2/.well-known/openid-configuration` - OIDC Discovery

## SSO 사용법

### 1. Client 등록

보안상 Client 등록은 DB에서 직접 수행합니다.

```sql
-- Public Client (SPA, 모바일 앱)
INSERT INTO oauth2_clients (
    id, client_id, client_secret, name,
    client_type, redirect_uri, grant_types, scopes, is_active
) VALUES (
    gen_random_uuid(), 'my-spa-app', NULL, '프론트엔드 앱',
    'public', 'http://localhost:3000/callback',
    'authorization_code,refresh_token', 'openid profile email', true
);

-- Confidential Client (서버 사이드 앱)
INSERT INTO oauth2_clients (
    id, client_id, client_secret, name,
    client_type, redirect_uri, grant_types, scopes, is_active
) VALUES (
    gen_random_uuid(), 'my-backend', 'your-secret-here', '백엔드 서비스',
    'confidential', 'http://service.example.com/callback',
    'authorization_code,refresh_token', 'openid profile email', true
);
```

### 2. Authorization Code Flow

```
1. 사용자를 /api/oauth2/authorize?client_id=...&redirect_uri=...&response_type=code 로 리다이렉트
2. IdP 로그인 완료 후 redirect_uri?code=... 로 리다이렉트
3. code를 POST /api/oauth2/token 으로 교환 → Access/Refresh/ID Token 획득
4. Access Token으로 GET /api/oauth2/userinfo 호출 → 사용자 정보 조회
```

PKCE 사용 시 `code_challenge`, `code_challenge_method=S256` 파라미터 추가.

### 3. MSA 토큰 검증

다른 서비스에서 IdP가 발급한 토큰 검증:

```
1. GET /api/oauth2/jwks 로 공개키(JWKS) 조회
2. 공개키로 JWT 서명 검증 (RS256)
3. 만료시간(exp), 토큰 타입(type) 클레임 확인
```
