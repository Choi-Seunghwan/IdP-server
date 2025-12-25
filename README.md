# Identity Service

SSO를 위한 통합 인증 서비스 - FastAPI 기반

## 주요 기능

- **이메일 회원가입/로그인** - JWT 기반 인증
- **소셜 로그인** - Google, Kakao, Naver OAuth2
- **본인인증** - SMS/휴대폰 인증
- **계정 연결** - 여러 인증 수단을 하나의 계정에 연결
- **SSO** - 다른 서비스에서 사용 가능한 토큰 발급

## 기술 스택

- **Framework**: FastAPI
- **Database**: PostgreSQL
- **ORM**: SQLAlchemy

## 프로젝트 구조

```
identity-service/
├── app/
│   ├── core/              # 핵심 기능 (DB, Security, Exceptions)
│   ├── user/              # 회원 도메인
│   ├── auth/              # 인증 도메인
│   ├── social/            # 소셜 로그인 도메인
│   ├── verification/      # 본인인증 도메인
│   └── sso/               # SSO 도메인
│
├── tests/                 # 테스트
├── migrations/            # Alembic 마이그레이션
├── pyproject.toml
├── .env.example
└── README.md
```

### 도메인 구조 (DDD + Clean Architecture)

각 도메인은 다음 구조를 따름

```
domain/
├── model.py          # 엔티티
├── dto.py            # DTO
├── persistence.py    # Repository (인터페이스 + 구현체)
├── service.py        # 비즈니스 로직
├── di.py             # Dependency Injection
└── api.py            # 라우터
```

## 시작하기

### 1. 환경 설정

```bash
# .env 파일 생성
cp .env.example .env

# .env 파일 수정 (DATABASE_URL, SECRET_KEY 등)
```

### 2. 의존성 설치

```bash
# uv로 가상환경 및 패키지 설치
uv sync
```

### 3. 데이터베이스 마이그레이션

```bash
# Alembic 초기화 (최초 1회)
alembic init migrations

# 마이그레이션 생성
alembic revision --autogenerate -m "Initial migration"

# 마이그레이션 실행
alembic upgrade head
```

### 4. 서버 실행

```bash
# 개발 서버 실행
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API 문서: http://localhost:8000/docs
