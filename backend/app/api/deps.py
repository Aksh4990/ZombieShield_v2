from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import decode_access_token, role_at_least
from app.db.session import get_db
from app.models import AuditLog

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    username: str
    role: str


def current_user(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> CurrentUser:
    if get_settings().auth_disabled:
        return CurrentUser("local-admin", "admin")
    token = credentials.credentials if credentials else request.query_params.get("token")  # query token only for EventSource streams
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"}) from exc
    return CurrentUser(payload["sub"], payload.get("role", "viewer"))


def require(role: str):
    def checker(user: CurrentUser = Depends(current_user)) -> CurrentUser:
        if not role_at_least(user.role, role):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires the {role} role")
        return user
    return checker


viewer = require("viewer")
analyst = require("analyst")
admin = require("admin")


def audit(db: Session, user: CurrentUser, action: str, target_type: str | None = None, target_id: str | None = None, **details) -> None:
    db.add(AuditLog(username=user.username, action=action, target_type=target_type, target_id=target_id, details=details))


DB = Depends(get_db)
