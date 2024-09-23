# backend/database.py

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLite URL format
SQLALCHEMY_DATABASE_URL = "sqlite:///./gaming_platform.db"

# Connect arguments for SQLite to enforce Foreign Key constraints
connect_args = {"check_same_thread": False}

# Create the SQLAlchemy engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args=connect_args
)

# Create a configured "Session" class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a base class for our ORM models
Base = declarative_base()
