# Identity Service

사내 SSO를 위한 통합 인증 서비스 - FastAPI 기반

## 주요 기능

- **이메일 회원가입/로그인** - JWT 기반 인증 (RS256/HS256 지원)
- **소셜 로그인** - Google, Kakao, Naver OAuth2
  - Google 계정 선택 화면 지원 (`prompt=select_account`)
  - IdP 로그인 페이지에서 소셜 로그인 제공
- **SSO (OAuth2/OIDC)** - 사내 서비스 통합 인증
  - OAuth2 Authorization Code Flow
  - OpenID Connect (ID Token, UserInfo, JWKS, Discovery)
  - Client 등록 및 관리 (Confidential/Public)
  - PKCE 지원
- **MSA 환경 지원**
  - RS256 비대칭키로 토큰 발급
  - JWKS 엔드포인트로 공개키 제공
  - 다른 서비스에서 공개키로 토큰 검증 가능

## 기술 스택

- **Framework**: FastAPI
- **Database**: PostgreSQL (async)
- **ORM**: SQLAlchemy 2.0
- **패키지 매니저**: uv
- **JWT**: python-jose (RS256/HS256 지원)
- **캐싱**: Redis (OAuth state 관리)

## 프로젝트 구조

```
app/
├── core/          # 핵심 기능 (DB, Security, Exceptions)
├── user/          # 회원 도메인
├── auth/          # 인증 도메인
├── social/        # 소셜 로그인 도메인
└── sso/           # SSO 도메인 (OAuth2/OIDC)
```

각 도메인은 DDD + Clean Architecture 패턴을 따름
- `model.py` - 엔티티
- `dto.py` - DTO
- `persistence.py` - Repository
- `service.py` - 비즈니스 로직
- `api.py` - 라우터

## 시작하기

### 1. 환경 설정

```bash
# .env 파일 생성 및 설정
cp .env.example .env
# DATABASE_URL, SECRET_KEY 등 설정
```

### 2. 의존성 설치

```bash
uv sync
```

### 3. RSA 키 생성 (RS256 사용 시)

```bash
# RS256을 사용하려면 RSA 키 쌍 생성 필요
uv run python scripts/generate_rsa_keys.py
```

`.env` 파일에 설정:
```env
ALGORITHM=RS256
RSA_PRIVATE_KEY_PATH=keys/private_key.pem
RSA_PUBLIC_KEY_PATH=keys/public_key.pem
```

### 4. 데이터베이스 마이그레이션

```bash
# 마이그레이션 실행
uv run alembic upgrade head
```

### 5. 서버 실행

```bash
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**API 문서**: http://localhost:8000/docs  
**Health Check**: http://localhost:8000/health

## 주요 API 엔드포인트

### 사용자 관리
- `POST /api/users` - 회원가입
- `GET /api/users/me` - 프로필 조회
- `PATCH /api/users/me` - 프로필 수정
- `PATCH /api/users/me/password` - 비밀번호 변경

### 인증
- `POST /api/auth/login` - 로그인
- `POST /api/auth/refresh` - 토큰 갱신
- `POST /api/auth/logout` - 로그아웃

### 소셜 로그인
- `GET /api/social/{provider}/login` - 소셜 로그인 URL 생성
- `GET /api/social/{provider}/callback` - OAuth 콜백 처리
- `GET /api/social/accounts` - 내 소셜 계정 목록
- `POST /api/social/connect` - 소셜 계정 연결

### SSO (OAuth2/OIDC)
- `POST /api/oauth2/clients` - Client 등록
- `GET /api/oauth2/login` - **IDP 로그인 페이지** (HTML)
- `GET /api/oauth2/authorize` - Authorization 요청
- `POST /api/oauth2/token` - Token 교환
- `GET /api/oauth2/userinfo` - 사용자 정보
- `GET /api/oauth2/jwks` - **공개키 (JWKS)** MSA용
- `GET /api/oauth2/.well-known/openid-configuration` - OIDC 메타데이터

## 빠른 시작 가이드

### SSO 사용 방법

#### 1. Client 등록

```bash
POST /api/oauth2/clients
{
  "name": "내부 관리 시스템",
  "description": "관리자 대시보드",
  "client_type": "public",  # 또는 "confidential"
  "redirect_uri": "http://localhost:3000/callback",
  "scopes": "openid profile email"
}
```

#### 2. OAuth2 Authorization Code Flow

1. 사용자를 `/api/oauth2/authorize?client_id=xxx&redirect_uri=xxx`로 리다이렉트
2. 로그인하지 않았으면 → IDP 로그인 페이지로 이동
3. 로그인 후 Authorization Code 받음
4. Code를 `/api/oauth2/token`으로 교환하여 Access Token 획득
5. Access Token으로 `/api/oauth2/userinfo`에서 사용자 정보 조회

### MSA 환경에서 토큰 검증

다른 서비스에서 이 Identity Service가 발급한 JWT 토큰을 검증하려면:

1. JWKS 엔드포인트에서 공개키 가져오기: `GET /api/oauth2/jwks`
2. 공개키로 토큰 검증

