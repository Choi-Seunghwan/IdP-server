import pytest

pytestmark = pytest.mark.api


class TestSignup:
    """회원가입 API"""

    async def test_success(self, client):
        response = await client.post("/api/users", json={
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "username": "newuser"
        })

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert "password" not in data

    async def test_duplicate_email(self, client, user_factory):
        await user_factory(email="existing@example.com")

        response = await client.post("/api/users", json={
            "email": "existing@example.com",
            "password": "SecurePass123!"
        })
        assert response.status_code == 409

    async def test_invalid_input(self, client):
        """유효성 검사 실패 (잘못된 이메일)"""
        response = await client.post("/api/users", json={
            "email": "not-an-email",
            "password": "SecurePass123!",
        })
        assert response.status_code == 422


class TestLogin:
    """로그인 API"""

    async def test_success(self, client, user_factory):
        await user_factory(email="login@example.com", password="MyPassword123!")

        response = await client.post("/api/auth/login", json={
            "email": "login@example.com",
            "password": "MyPassword123!"
        })

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data

    async def test_wrong_password(self, client, user_factory):
        await user_factory(email="wrongpass@example.com", password="CorrectPassword123!")

        response = await client.post("/api/auth/login", json={
            "email": "wrongpass@example.com",
            "password": "WrongPassword123!"
        })
        assert response.status_code == 401

    async def test_user_not_found(self, client):
        response = await client.post("/api/auth/login", json={
            "email": "notexist@example.com",
            "password": "SomePassword123!"
        })
        assert response.status_code == 401


class TestTokenRefresh:
    """토큰 갱신 API"""

    async def test_success(self, client, user_factory):
        await user_factory(email="refresh@example.com", password="MyPassword123!")

        login_res = await client.post("/api/auth/login", json={
            "email": "refresh@example.com",
            "password": "MyPassword123!"
        })

        response = await client.post("/api/auth/refresh", json={
            "refresh_token": login_res.json()["refresh_token"]
        })

        assert response.status_code == 200
        assert "access_token" in response.json()

    async def test_invalid_token(self, client):
        response = await client.post("/api/auth/refresh", json={
            "refresh_token": "invalid.token.here"
        })
        assert response.status_code == 401
