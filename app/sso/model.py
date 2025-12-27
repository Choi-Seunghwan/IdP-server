import enum
import uuid
from datetime import datetime, UTC
from sqlalchemy import String, DateTime, Boolean, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class ClientType(str, enum.Enum):
    """OAuth2 Client 타입"""

    CONFIDENTIAL = "confidential"  # 서버 사이드 앱 (client_secret 필요)
    PUBLIC = "public"  # 클라이언트 사이드 앱 (SPA, 모바일 앱)


class GrantType(str, enum.Enum):
    """지원하는 OAuth2 Grant Type"""

    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"


class OAuth2Client(Base):
    """
    OAuth2 Client 모델
    사내 서비스들이 이 IdP를 사용하기 위해 등록되는 클라이언트 정보
    """

    __tablename__ = "oauth2_clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Client 식별자 (OAuth2 표준)
    client_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    client_secret: Mapped[str | None] = mapped_column(
        String(255), nullable=True  # Public 클라이언트는 None
    )

    # Client 정보
    name: Mapped[str] = mapped_column(String(255), nullable=False)  # 서비스 이름
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Client 타입
    client_type: Mapped[ClientType] = mapped_column(
        SQLEnum(ClientType), nullable=False, default=ClientType.CONFIDENTIAL
    )

    # Redirect URI (콜백 URL)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)

    # 지원하는 Grant Type
    grant_types: Mapped[str] = mapped_column(
        Text, nullable=False, default="authorization_code,refresh_token"
    )  # 콤마로 구분된 문자열

    # 스코프 (기본: openid profile email)
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default="openid profile email")

    # 활성화 여부
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # 생성/수정 시간
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


class AuthorizationCode(Base):
    """
    OAuth2 Authorization Code 모델
    Authorization Code Flow에서 발급된 코드를 임시 저장
    토큰 교환 후 삭제됨
    """

    __tablename__ = "authorization_codes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Authorization Code 값
    code: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    # Client 정보
    client_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # 사용자 정보
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Redirect URI (검증용)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)

    # 요청된 스코프
    scopes: Mapped[str] = mapped_column(Text, nullable=False)

    # PKCE (선택사항)
    code_challenge: Mapped[str | None] = mapped_column(String(255), nullable=True)
    code_challenge_method: Mapped[str | None] = mapped_column(
        String(10), nullable=True  # "plain" or "S256"
    )

    # State (CSRF 방지용)
    state: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # 만료 시간 (보통 10분)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # 사용 여부 (토큰 교환 시 True로 변경)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)

    # 생성 시간
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
