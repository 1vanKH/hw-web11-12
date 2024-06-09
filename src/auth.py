from fastapi import APIRouter, HTTPException, Depends, status, Path, Query, Security
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from src.auth_services import Auth
from src.schemas import TokenSchema, UserSchema, UserResponse
from src.repository.users import get_user_by_email, create_user, get_user_by_email, update_token
from src.database.db import get_db


router = APIRouter(prefix='/auth', tags=['auth'])
get_refresh_token = HTTPBearer()


@router.post("/signup/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def signup(body: UserSchema, db: Session = Depends(get_db)):
    if get_user_by_email(body.email, db):
        print(1)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",

        )

    body.password = Auth.get_password_hash(body.password)
    db_user = create_user(body, db)

    return db_user



@router.post("/login/", response_model=TokenSchema)
def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = get_user_by_email(body.username, db)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    if not Auth.verify_password(body.password, db_user.password):

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    access_token = Auth.create_access_token(data={'sub': db_user.email})
    refresh_token = Auth.create_refresh_token(data={'sub': db_user.email})
    update_token(db_user, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.get("/refresh_token/", response_model=TokenSchema)
def refresh_token(credentials: HTTPAuthorizationCredentials = Security(get_refresh_token),
                           db: Session = Depends(get_db)):
    token = credentials.credentials
    email = Auth.decode_refresh_token()
    user = get_user_by_email(email, db)
    if user.refresh_token != token:
        update_token(user, None, db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    access_token = Auth.create_access_token(data={'sub': email})
    refresh_token = Auth.create_refresh_token(data={'sub': email})
    update_token(user, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}