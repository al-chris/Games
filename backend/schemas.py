# backend/schemas.py

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class UserBase(BaseModel):
    id: str
    username: Optional[str] = None
    is_guest: bool
    is_admin: bool  # Included for admin status

    class Config:
        orm_mode = True

class UserCreate(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: str
    username: Optional[str] = None
    is_guest: bool

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[str] = None

class SessionBase(BaseModel):
    id: str
    game_type: str
    mode: Optional[str] = None
    creator_id: str
    is_active: bool
    current_turn: Optional[str] = None

class SessionCreate(BaseModel):
    game_type: str
    mode: Optional[str] = None

class SessionOut(BaseModel):
    session_id: str
    creator_id: str

class JoinSession(BaseModel):
    session_id: str

class ContributionBase(BaseModel):
    user_id: str
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class GenerateStoryIn(BaseModel):
    session_id: str

class SessionSearchResult(BaseModel):
    session_id: str
    game_type: str
    mode: Optional[str] = None
    creator_id: str
    participants_count: int
    is_active: bool

    class Config:
        orm_mode = True

class SearchResults(BaseModel):
    users: List[UserOut]
    sessions: List[SessionSearchResult]
