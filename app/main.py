from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings

from app.user.api import router as user_router
from app.auth.api import router as auth_router
from app.social.api import router as social_router
from app.sso.api import router as sso_router


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api_prefix = "/api"
    app.include_router(user_router, prefix=api_prefix)
    app.include_router(auth_router, prefix=api_prefix)
    app.include_router(social_router, prefix=api_prefix)
    app.include_router(sso_router, prefix=api_prefix)  # SSO 라우터 등록

    @app.get("/health")
    async def healch_check():
        return {"status": "healthy"}

    return app


app = create_app()
