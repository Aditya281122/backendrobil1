
from pydantic import BaseModel
from typing import List, Dict, Any
import uuid
from datetime import datetime

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    phone: str | None = None

class UserBase(BaseModel):
    phone: str
    full_name: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_verified: bool
    created_at: datetime

    class Config:
        from_attributes = True

class ClientAction(BaseModel):
    client_id: uuid.UUID
    type: str
    payload: Dict[str, Any]
    timestamp: datetime

class SyncBatch(BaseModel):
    device_id: str
    app_version: str
    client_actions: List[ClientAction]

class SyncResponse(BaseModel):
    status: str
    processed_actions: Dict[uuid.UUID, Dict[str, Any]]
