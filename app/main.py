from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.redis import close_redis

from app.user.api import router as user_router
from app.auth.api import router as auth_router
from app.social.api import router as social_router
from app.sso.api import router as sso_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """애플리케이션 생명주기 관리"""
    # 시작 시
    yield
    # 종료 시
    await close_redis()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.get_allowed_origins_list(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api_prefix = "/api"
    app.include_router(user_router, prefix=api_prefix)
    app.include_router(auth_router, prefix=api_prefix)
    app.include_router(social_router, prefix=api_prefix)
    app.include_router(sso_router, prefix=api_prefix)

    @app.get("/health")
    async def healch_check():
        return {"status": "healthy"}

    return app


app = create_app()
