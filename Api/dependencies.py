from http import HTTPStatus
from typing import Annotated, Optional
from fastapi import Depends, HTTPException
import jwt
from config import SECRET_KEY,ALGORITHM,oauth2_scheme
from crud import get_user_by_username
from schemas import User,TokenData
from database import SessionLocal
from jwt.exceptions import InvalidTokenError
from sqlalchemy.orm import sessionmaker, Session


# --------------------------
# Dependências do Banco de Dados (dependencies.py)
# --------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



# --------------------------
# Dependências de Autenticação (dependencies.py)
# --------------------------
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=HTTPStatus.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
