"""
Authentication module — JWT tokens with role-based access.

Roles:
  - admin: full access to dashboard
  - user: access to /api/* endpoints only, no dashboard

Passwords stored as bcrypt hashes in SQLite (not plaintext, not in memory).
"""

import os
import time
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Request

# Secret key из settings (который читает из .env)
def _get_secret_key():
    try:
        from config.settings import settings
        return settings.jwt_secret_key
    except Exception:
        return os.environ.get("JWT_SECRET_KEY", "as-9f4k2m8x1p7q3r6t5v0w-diploma-2026-shield")

SECRET_KEY = _get_secret_key()
ALGORITHM = "HS256"
TOKEN_EXPIRE_SECONDS = 3600

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify plaintext password against bcrypt hash."""
    return pwd_context.verify(plain, hashed)


async def verify_user(username: str, password: str) -> Optional[dict]:
    """Verify credentials from SQLite. Returns user info or None."""
    try:
        from app.core.database import UserDB
        user = await UserDB.get_user(username)
        if not user:
            return None
        if not verify_password(password, user["password_hash"]):
            return None
        return {
            "username": user["username"],
            "role": user["role"],
            "name": user["name"],
        }
    except Exception:
        return None


def create_token(username: str, role: str) -> str:
    """Create a signed JWT token."""
    payload = {
        "sub": username,
        "role": role,
        "exp": int(time.time()) + TOKEN_EXPIRE_SECONDS,
        "iat": int(time.time()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate JWT signature and expiry."""
    try:
        payload = jwt.decode(
            token, SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": True}
        )
        return payload
    except JWTError:
        return None


# ── JWT BLACKLIST ─────────────────────────────────────────────
# После logout токен добавляется в Redis blacklist.
# Живёт в blacklist ровно до своего истечения — не дольше.

async def blacklist_token(token: str) -> bool:
    """Add token to Redis blacklist on logout."""
    try:
        from app.core import get_redis
        r = await get_redis()
        # Узнаём сколько осталось жить токену
        payload = decode_token(token)
        if payload:
            remaining = int(payload.get("exp", 0)) - int(time.time())
            if remaining > 0:
                await r.setex(f"shield:blacklist:{token}", remaining, "1")
                return True
    except Exception:
        pass
    return False


async def is_token_blacklisted(token: str) -> bool:
    """Check if token is in Redis blacklist."""
    try:
        from app.core import get_redis
        r = await get_redis()
        return await r.exists(f"shield:blacklist:{token}") > 0
    except Exception:
        return False


def get_token_from_request(request: Request) -> Optional[str]:
    """Extract JWT token from Authorization header, cookie, or X-Auth-Token."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    token = request.cookies.get("as_token")
    if token:
        return token
    token = request.cookies.get("shield_token")
    if token:
        return token
    token = request.headers.get("X-Auth-Token")
    if token:
        return token
    return None


def get_current_user(request: Request) -> Optional[dict]:
    """Get current authenticated user (sync — does NOT check blacklist)."""
    token = get_token_from_request(request)
    if not token:
        return None
    return decode_token(token)


async def get_current_user_async(request: Request) -> Optional[dict]:
    """Get current user — checks Redis blacklist. Use in async endpoints."""
    token = get_token_from_request(request)
    if not token:
        return None
    if await is_token_blacklisted(token):
        return None
    return decode_token(token)


def require_role(request: Request, required_role: str) -> Optional[dict]:
    """Check if current user has required role."""
    user = get_current_user(request)
    if not user:
        return None
    if required_role == "admin" and user.get("role") != "admin":
        return None
    return user
