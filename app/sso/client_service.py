import secrets
import uuid
from app.sso.model import OAuth2Client, ClientType
from app.sso.dto import CreateClientDto, ClientDto
from app.sso.persistence import OAuth2ClientRepository
from app.core.exceptions import NotFoundException


class ClientService:
    """
    OAuth2 Client 관리 서비스
    사내 서비스들을 Client로 등록/관리
    """

    def __init__(self, client_repository: OAuth2ClientRepository):
        self.client_repository = client_repository

    async def create_client(self, dto: CreateClientDto) -> ClientDto:
        """
        새로운 OAuth2 Client 등록
        client_id와 client_secret 자동 생성
        """
        # client_id 생성 (랜덤 문자열)
        client_id = f"client_{secrets.token_urlsafe(16)}"
        
        # client_secret 생성 (Confidential 클라이언트만)
        client_secret = None
        if dto.client_type == ClientType.CONFIDENTIAL:
            client_secret = secrets.token_urlsafe(32)

        # 중복 체크
        if await self.client_repository.exists_by_client_id(client_id):
            # 재시도 (거의 발생하지 않지만 안전을 위해)
            client_id = f"client_{secrets.token_urlsafe(16)}"

        # Client 엔티티 생성
        client = OAuth2Client(
            id=str(uuid.uuid4()),
            client_id=client_id,
            client_secret=client_secret,
            name=dto.name,
            description=dto.description,
            client_type=dto.client_type,
            redirect_uri=dto.redirect_uri,
            scopes=dto.scopes,
        )

        # 저장
        created_client = await self.client_repository.create(client)

        # DTO로 변환 (client_secret 포함 - 한 번만 보여줌)
        return ClientDto(
            id=created_client.id,
            client_id=created_client.client_id,
            name=created_client.name,
            description=created_client.description,
            client_type=created_client.client_type,
            redirect_uri=created_client.redirect_uri,
            scopes=created_client.scopes,
            is_active=created_client.is_active,
            created_at=created_client.created_at.isoformat(),
        )

    async def get_client_by_client_id(self, client_id: str) -> OAuth2Client:
        """Client ID로 Client 조회"""
        client = await self.client_repository.find_by_client_id(client_id)
        if not client:
            raise NotFoundException(detail=f"Client not found: {client_id}")
        if not client.is_active:
            raise NotFoundException(detail=f"Client is not active: {client_id}")
        return client

    async def verify_client_secret(
        self, client_id: str, client_secret: str | None
    ) -> OAuth2Client:
        """
        Client ID와 Secret 검증
        Public 클라이언트는 client_secret이 None이어야 함
        """
        client = await self.get_client_by_client_id(client_id)

        # Confidential 클라이언트는 secret 필수
        if client.client_type == ClientType.CONFIDENTIAL:
            if not client_secret or client.client_secret != client_secret:
                raise NotFoundException(detail="Invalid client credentials")

        # Public 클라이언트는 secret 없어야 함
        elif client.client_type == ClientType.PUBLIC:
            if client_secret:
                raise NotFoundException(detail="Public client should not provide secret")

        return client

