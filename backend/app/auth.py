"""Password hashing and short-lived JWT authentication helpers."""
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import User

_password_hasher = PasswordHasher(time_cost=2, memory_cost=19_456, parallelism=1)
_bearer = HTTPBearer(auto_error=False)
ISSUER = "webguard-security-lab"
AUDIENCE = "webguard-api"
DUMMY_PASSWORD_HASH = _password_hasher.hash("constant-time-dummy-password-not-a-real-account")


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError):
        return False


def create_access_token(user: User, settings: Settings) -> tuple[str, int]:
    ttl_seconds = settings.access_token_ttl_minutes * 60
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": user.id,
            "email": user.email,
            "iat": now,
            "exp": now + timedelta(seconds=ttl_seconds),
            "iss": ISSUER,
            "aud": AUDIENCE,
        },
        settings.secret_key,
        algorithm="HS256",
    )
    return token, ttl_seconds


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required",
                            headers={"WWW-Authenticate": "Bearer"})
    settings: Settings = request.app.state.settings
    try:
        claims = jwt.decode(
            credentials.credentials,
            settings.secret_key,
            algorithms=["HS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["sub", "exp", "iat", "iss", "aud"]},
        )
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise jwt.InvalidTokenError("Missing subject")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired access token",
                            headers={"WWW-Authenticate": "Bearer"}) from exc

    with request.app.state.db.SessionLocal() as db:  # type: Session
        user = db.scalar(select(User).where(User.id == subject))
        if user is None or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account unavailable",
                                headers={"WWW-Authenticate": "Bearer"})
        # Return an expunged snapshot so the dependency's short DB session may safely close.
        db.expunge(user)
        return user


def require_operator(user: User = Depends(get_current_user)) -> User:
    if user.role not in {"admin", "operator"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator or admin role required")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user
