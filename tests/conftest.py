import pytest
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from faker import Faker
import uuid

from app.core.database import Base, get_db
from app.user.model import User
from app.config import Settings

fake = Faker()


@pytest.fixture
def test_settings() -> Settings:
    """테스트용 설정"""
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        redis_url="redis://localhost:6379/1",
        secret_key="test-secret-key-for-testing-only",
        algorithm="HS256",
        debug=True,
        environment="test",
    )


@pytest.fixture
async def test_db_engine():
    """테스트용 DB 엔진"""
    from sqlalchemy.pool import StaticPool

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest.fixture
async def test_db(test_db_engine) -> AsyncGenerator[AsyncSession, None]:
    """테스트용 DB 세션 (트랜잭션 롤백)"""
    async_session = async_sessionmaker(
        test_db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )

    async with async_session() as session:
        async with session.begin():
            yield session
            await session.rollback()


@pytest.fixture
async def test_redis():
    """테스트용 Redis 클라이언트"""
    from redis.asyncio import Redis

    redis_client = Redis.from_url(
        "redis://localhost:6379/1",
        encoding="utf-8",
        decode_responses=True,
    )

    yield redis_client

    await redis_client.flushdb()
    await redis_client.aclose()


@pytest.fixture(scope="session")
def rsa_keypair():
    """RS256 테스트용 RSA 키쌍 생성"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {
        "private_key": private_key,
        "public_key": public_key,
        "private_pem": private_pem,
        "public_pem": public_pem,
    }


@pytest.fixture
def user_factory(test_db: AsyncSession):
    """테스트용 User 생성 팩토리"""
    async def _create_user(
        email: str | None = None,
        password: str | None = "password123",
        username: str | None = None,
        is_active: bool = True,
        is_verified: bool = False,
        hashed_password: str | None = None,
    ) -> User:
        from app.core.security import hash_password

        user = User(
            id=str(uuid.uuid4()),
            email=email or fake.email(),
            username=username or fake.user_name(),
            hashed_password=hashed_password or (hash_password(password) if password else None),
            is_active=is_active,
            is_verified=is_verified,
        )

        test_db.add(user)
        await test_db.flush()
        await test_db.refresh(user)

        return user

    return _create_user


@pytest.fixture
async def client(test_db: AsyncSession, test_settings, monkeypatch):
    """API 테스트용 HTTP 클라이언트"""
    from httpx import AsyncClient, ASGITransport
    from app.main import app

    monkeypatch.setattr("app.config.settings", test_settings)

    async def _override_db():
        yield test_db

    app.dependency_overrides[get_db] = _override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
