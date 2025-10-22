
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime
import database

class User(database.Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    phone = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    actions = relationship("UserAction", back_populates="user")

class Product(database.Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    ean = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    stock = Column(Integer, default=0)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Sale(database.Base):
    __tablename__ = "sales"

    id = Column(Integer, primary_key=True, index=True)
    total_amount = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class UserAction(database.Base):
    __tablename__ = "user_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    client_id = Column(String, unique=True, index=True, nullable=False) # The client's unique action ID
    type = Column(String, nullable=False)
    payload = Column(JSON, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    processed_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="actions")
