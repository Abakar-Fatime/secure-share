from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class AcceptInviteIn(BaseModel):
    token: str = Field(min_length=20, max_length=100)
    password: str = Field(min_length=1, max_length=200)
    name: str | None = Field(default=None, max_length=100)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=1, max_length=200)


class InviteIn(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=100)
    role: str = Field(pattern="^(admin|member|viewer)$")


class UserUpdateIn(BaseModel):
    role: str | None = Field(default=None, pattern="^(admin|member|viewer)$")
    status: str | None = Field(default=None, pattern="^(active|disabled)$")
    reset_mfa: bool = False


class UploadIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    size: int = Field(gt=0)
    content_type: str = Field(default="application/octet-stream", max_length=120)


class GrantIn(BaseModel):
    email: EmailStr


class LinkIn(BaseModel):
    expires_in_hours: int = Field(default=24, ge=1)
    max_downloads: int | None = Field(default=None, ge=1, le=1000)
    password: str | None = Field(default=None, min_length=4, max_length=200)


class PublicDownloadIn(BaseModel):
    password: str | None = Field(default=None, max_length=200)
