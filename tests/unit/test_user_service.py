import pytest
from unittest.mock import patch

from app.user.dto import CreateUserDto, UpdateUserDto, ChangePasswordDto
from app.core.exceptions import ConflictException, NotFoundException, BadRequestException, UnauthorizedException
from tests.helpers import make_mock_user

pytestmark = pytest.mark.unit


class TestCreateUser:
    @patch("app.user.service.User")
    async def test_success(self, _, user_service, mock_repo):
        mock_repo.exists_by_email.return_value = False
        mock_repo.create.return_value = make_mock_user(email="new@example.com")

        dto = CreateUserDto(email="new@example.com", password="Password123!")
        result = await user_service.create_user(dto)

        assert result.email == "new@example.com"

    async def test_duplicate_email(self, user_service, mock_repo):
        mock_repo.exists_by_email.return_value = True

        with pytest.raises(ConflictException):
            await user_service.create_user(CreateUserDto(email="existing@example.com", password="Password123!"))


class TestGetUserById:
    async def test_success(self, user_service, mock_repo):
        mock_repo.find_by_id.return_value = make_mock_user()

        result = await user_service.get_user_by_id("user-123")
        assert result.id == "user-123"

    async def test_not_found(self, user_service, mock_repo):
        mock_repo.find_by_id.return_value = None

        with pytest.raises(NotFoundException):
            await user_service.get_user_by_id("nonexistent")


class TestUpdateUser:
    async def test_success(self, user_service, mock_repo):
        user = make_mock_user()
        mock_repo.find_by_id.return_value = user
        mock_repo.update.return_value = user

        await user_service.update_user("user-123", UpdateUserDto(username="updated"))
        assert user.username == "updated"

    async def test_not_found(self, user_service, mock_repo):
        mock_repo.find_by_id.return_value = None

        with pytest.raises(NotFoundException):
            await user_service.update_user("nonexistent", UpdateUserDto(username="new"))


class TestChangePassword:
    async def test_success(self, user_service, mock_repo):
        mock_repo.find_by_id.return_value = make_mock_user(password="Password123!")

        dto = ChangePasswordDto(old_password="Password123!", new_password="NewPassword456!")
        await user_service.change_password("user-123", dto)
        mock_repo.update.assert_awaited_once()

    async def test_wrong_old_password(self, user_service, mock_repo):
        mock_repo.find_by_id.return_value = make_mock_user(password="Password123!")

        with pytest.raises(BadRequestException):
            await user_service.change_password("user-123", ChangePasswordDto(old_password="Wrong!", new_password="NewPass123!"))


class TestAuthenticateUser:
    async def test_success(self, user_service, mock_repo):
        mock_repo.find_by_email.return_value = make_mock_user(password="Password123!")

        result = await user_service.authenticate_user("test@example.com", "Password123!")
        assert result.email == "test@example.com"

    async def test_wrong_password(self, user_service, mock_repo):
        mock_repo.find_by_email.return_value = make_mock_user(password="Password123!")

        with pytest.raises(UnauthorizedException):
            await user_service.authenticate_user("test@example.com", "WrongPassword!")

    async def test_user_not_found(self, user_service, mock_repo):
        mock_repo.find_by_email.return_value = None

        with pytest.raises(UnauthorizedException):
            await user_service.authenticate_user("notfound@example.com", "any")


class TestDeleteUser:
    async def test_success(self, user_service, mock_repo):
        user = make_mock_user()
        mock_repo.find_by_id.return_value = user

        await user_service.delete_user("user-123")
        mock_repo.delete.assert_awaited_once_with(user)

    async def test_not_found(self, user_service, mock_repo):
        mock_repo.find_by_id.return_value = None

        with pytest.raises(NotFoundException):
            await user_service.delete_user("nonexistent")
