from typing import Annotated, Optional
from pydantic import BaseModel


# --------------------------
# Schemas Pydantic (schemas.py)
# --------------------------
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    disabled: Optional[bool] = None

    class Config:
        orm_mode = True


