# backend/create_initial_admin.py

import sys
import os
from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models
from passlib.context import CryptContext
from uuid import uuid4

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def create_initial_admin(username: str, password: str):
    db: Session = SessionLocal()
    try:
        existing_admin = db.query(models.User).filter(models.User.is_admin == True).first()
        if existing_admin:
            print("Admin user already exists.")
            return
        
        # Check if username is already taken
        existing_user = db.query(models.User).filter(models.User.username == username).first()
        if existing_user:
            print("Username already taken. Choose a different username.")
            return
        
        admin_user = models.User(
            id=str(uuid4()),
            username=username,
            hashed_password=get_password_hash(password),
            is_guest=False,
            is_admin=True
        )
        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)
        print(f"Admin user '{username}' created successfully with ID: {admin_user.id}")
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python create_initial_admin.py <username> <password>")
    else:
        username = sys.argv[1]
        password = sys.argv[2]
        create_initial_admin(username, password)

# python create_initial_admin.py admin_username secure_password
