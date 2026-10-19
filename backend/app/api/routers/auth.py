from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DB, CurrentUser, admin, audit, current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.models import User
from app.schemas import LoginRequest, TokenResponse, UserCreate, UserRead

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = DB) -> TokenResponse:
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    audit(db, CurrentUser(user.username, user.role), "auth.login")
    db.commit()
    return TokenResponse(access_token=create_access_token(user.username, user.role), username=user.username, role=user.role)


@router.get("/auth/me")
def me(user: CurrentUser = Depends(current_user)) -> dict:
    return {"username": user.username, "role": user.role}


@router.get("/users", response_model=list[UserRead])
def list_users(db: Session = DB, _: CurrentUser = Depends(admin)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.username)))


@router.post("/users", response_model=UserRead, status_code=201)
def create_user(payload: UserCreate, db: Session = DB, user: CurrentUser = Depends(admin)) -> User:
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(409, "Username already exists")
    record = User(username=payload.username, password_hash=hash_password(payload.password), role=payload.role)
    db.add(record)
    audit(db, user, "user.create", "user", payload.username, role=payload.role)
    db.commit()
    return record
