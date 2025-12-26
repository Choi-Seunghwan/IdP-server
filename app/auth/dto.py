from pydantic import BaseModel, EmailStr


# 로그인 요청
class LoginDto(BaseModel):
    email: EmailStr
    password: str


# 토큰 응답
class TokenDto(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# Access Token 응답 (갱신 시)
class AccessTokenDto(BaseModel):
    access_token: str
    token_type: str = "bearer"


# Refresh Token 요청
class RefreshTokenDto(BaseModel):
    refresh_token: str
