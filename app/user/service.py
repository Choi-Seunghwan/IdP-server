import uuid
from app.core.exceptions import (
    BadRequestException,
    ConflictException,
    NotFoundException,
    UnauthorizedException,
)
from app.core.security import hash_password, verify_password
from app.user.dto import ChangePasswordDto, CreateUserDto, UpdateUserDto, UserDto
from app.user.model import User
from app.user.persistence import UserRepository


class UserService:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository

    async def create_user(self, dto: CreateUserDto) -> UserDto:
        """회원가입"""
        # 이메일 중복 체크
        if await self.user_repository.exists_by_email(dto.email):
            raise ConflictException(detail="Email already exists")

        # User 엔티티 생성
        user = User(
            id=str(uuid.uuid4()),
            email=dto.email,
            hashed_password=hash_password(dto.password),
            username=dto.username,
            phone_number=dto.phone_number,
        )

        created_user = await self.user_repository.create(user)

        return UserDto.model_validate(created_user)

    async def get_user_by_id(self, user_id: str) -> UserDto:
        """사용자 조회"""
        user = await self.user_repository.find_by_id(user_id)

        if not user:
            raise NotFoundException(detail="User not found")

        return UserDto.model_validate(user)

    async def update_user(self, user_id: str, dto: UpdateUserDto) -> UserDto:
        """사용자 정보 수정"""
        user = await self.user_repository.find_by_id(user_id)
        if not user:
            raise NotFoundException(detail="User not found")

        # 업데이트
        if dto.username is not None:
            user.username = dto.username
        if dto.phone_number is not None:
            user.phone_number = dto.phone_number

        updated_user = await self.user_repository.update(user)
        return UserDto.model_validate(updated_user)

    async def change_password(self, user_id: str, dto: ChangePasswordDto) -> None:
        """비밀번호 변경"""
        user = await self.user_repository.find_by_id(user_id)
        if not user:
            raise NotFoundException(detail="User not found")

        # 비밀번호가 설정 되지 않은 경우 (소셜 로그인만 있는 경우)
        if not user.hashed_password:
            raise BadRequestException(detail="Password not set")

        # 기존 비밀번호 확인
        if not verify_password(dto.old_password, user.hashed_password):
            raise BadRequestException(detail="Invalid old password")

        user.hashed_password = hash_password(dto.new_password)
        await self.user_repository.update(user)

    async def delete_user(self, user_id: str) -> None:
        """회원 탈퇴"""
        user = await self.user_repository.find_by_id(user_id)
        if not user:
            raise NotFoundException(detail="User not found")
        await self.user_repository.delete(user)

    async def authenticate_user(self, email: str, password: str) -> UserDto:
        """이메일과 비밀번호로 사용자 인증"""
        user = await self.user_repository.find_by_email(email)
        if not user:
            raise UnauthorizedException(detail="Invalid email or password")

        if not user.hashed_password:
            raise UnauthorizedException(detail="Please use social login")

        if not verify_password(password, user.hashed_password):
            raise UnauthorizedException(detail="Invalid email or password")

        if not user.is_active:
            raise UnauthorizedException(detail="User account is inactive")

        return UserDto.model_validate(user)

    async def create_social_user(self, email: str | None, username: str | None = None) -> UserDto:
        """소셜 로그인용 사용자 생성 (비밀번호 없음)"""
        # 이메일이 있으면 중복 체크
        if email:
            existing = await self.user_repository.find_by_email(email)
            if existing:
                # 이미 존재하는 경우 해당 사용자 반환
                return UserDto.model_validate(existing)

        # User 엔티티 생성 (비밀번호 없음)
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            hashed_password=None,  # 소셜 로그인만 사용
            username=username,
            is_active=True,
            is_verified=True,  # 소셜 로그인은 이미 검증됨
        )

        created_user = await self.user_repository.create(user)
        return UserDto.model_validate(created_user)

    async def has_password(self, user_id: str) -> bool:
        """사용자가 비밀번호를 설정했는지 확인"""
        user = await self.user_repository.find_by_id(user_id)
        if not user:
            raise NotFoundException(detail="User not found")
        return user.hashed_password is not None
