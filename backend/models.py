# backend/models.py

from sqlalchemy import Column, String, Boolean, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
import uuid

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    username = Column(String, unique=True, index=True, nullable=True)  # Nullable for guest users
    hashed_password = Column(String, nullable=True)  # Nullable for guest users
    is_guest = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)  # New field for admin users
    
    # Relationships
    sessions_created = relationship(
        "Session",
        back_populates="creator",
        foreign_keys="Session.creator_id"  # Specify the foreign key
    )
    contributions = relationship("Contribution", back_populates="user")

class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    game_type = Column(String, nullable=False)  # e.g., 'completion', 'questions'
    mode = Column(String, nullable=True)  # e.g., 'word', 'sentence', 'paragraph'
    creator_id = Column(String, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    current_turn = Column(String, ForeignKey("users.id"), nullable=True)  # user_id
    
    # Relationships
    creator = relationship(
        "User",
        back_populates="sessions_created",
        foreign_keys=[creator_id]  # Specify the foreign key
    )
    participants = relationship("SessionParticipant", back_populates="session", cascade="all, delete-orphan")
    contributions = relationship("Contribution", back_populates="session", cascade="all, delete-orphan")

class SessionParticipant(Base):
    __tablename__ = "session_participants"
    
    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    
    # Relationships
    session = relationship("Session", back_populates="participants")
    user = relationship("User")

class Contribution(Base):
    __tablename__ = "contributions"
    
    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    session_id = Column(String, ForeignKey("sessions.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    session = relationship("Session", back_populates="contributions")
    user = relationship("User", back_populates="contributions")