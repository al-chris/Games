# backend/main.py

import os
from fastapi import FastAPI, HTTPException, Depends, status, Request, Body, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from uuid import uuid4
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

from database import SessionLocal, engine
import models
import schemas

# Create all database tables
models.Base.metadata.create_all(bind=engine)

# Secret key for JWT
SECRET_KEY = os.getenv("SECRET_KEY")  # Replace with a secure key
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# Initialize FastAPI app
app = FastAPI()

# Retrieve CORS allowed origins from environment variable
CORS_ALLOWED_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "")
if CORS_ALLOWED_ORIGINS:
    # Split the string into a list, stripping any extra whitespace
    origins = [origin.strip() for origin in CORS_ALLOWED_ORIGINS.split(",")]
else:
    origins = []


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allows all origins, change as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -----------------------
# Authentication Utilities
# -----------------------

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Creates a JWT access token.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)  # Default 15 minutes
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def get_user_by_id(db: Session, user_id: str):
    return db.query(models.User).filter(models.User.id == user_id).first()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Retrieves the current user based on the JWT token.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = schemas.TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception
    user = get_user_by_id(db, user_id=token_data.user_id)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: models.User = Depends(get_current_user)):
    """
    Ensures that the current user is active.
    """
    # Implement any additional checks if needed
    return current_user

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        current_user: models.User = kwargs.get('current_user')
        if not current_user.is_admin:
            raise HTTPException(status_code=403, detail="Admin privileges required.")
        return func(*args, **kwargs)
    return wrapper

# -----------------------
# API Endpoints
# -----------------------

@app.post("/register", response_model=schemas.Token, tags=["Authentication"])
def register(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Registers a new user.
    """
    # Check if username already exists
    existing_user = get_user_by_username(db, user_in.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered.")
    
    # Create new user
    user = models.User(
        id=str(uuid4()),
        username=user_in.username,
        hashed_password=get_password_hash(user_in.password),
        is_guest=False
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.id},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=schemas.Token, tags=["Authentication"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Authenticates a user and returns a JWT token.
    """
    user = get_user_by_username(db, form_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password.")
    if user.is_guest:
        raise HTTPException(status_code=400, detail="Guest users cannot login with password.")
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password.")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.id},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/create_temp_user", response_model=schemas.Token, tags=["Authentication"])
def create_temp_user(db: Session = Depends(get_db)):
    """
    Creates a temporary guest user.
    """
    user = models.User(
        id=str(uuid4()),
        username=None,
        hashed_password=None,
        is_guest=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.id},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/create_session", response_model=schemas.SessionOut, tags=["Sessions"])
def create_session(session_in: schemas.SessionCreate, current_user: models.User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """
    Creates a new game session.
    """
    session = models.Session(
        id=str(uuid4()),
        game_type=session_in.game_type,
        mode=session_in.mode,
        creator_id=current_user.id,
        is_active=True,
        current_turn=current_user.id  # Creator starts
    )
    db.add(session)
    
    # Add creator as participant
    participant = models.SessionParticipant(
        id=str(uuid4()),
        session_id=session.id,
        user_id=current_user.id
    )
    db.add(participant)
    
    db.commit()
    db.refresh(session)
    
    return {"session_id": session.id, "creator_id": session.creator_id}

@app.get("/users", response_model=List[schemas.UserOut], tags=["Users"])
def get_all_users(
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves a paginated list of all users.
    Only accessible by admin users.
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this resource.")
    
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

@app.get("/active_sessions", response_model=List[schemas.SessionSearchResult], tags=["Sessions"])
def get_active_sessions(
    skip: int = 0,
    limit: int = 100,
    current_user: models.User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves a paginated list of all active sessions.
    Accessible by all authenticated users.
    """
    active_sessions = db.query(models.Session).filter(models.Session.is_active == True).offset(skip).limit(limit).all()
    
    results = []
    for session in active_sessions:
        participants_count = db.query(models.SessionParticipant).filter(
            models.SessionParticipant.session_id == session.id
        ).count()
        session_data = schemas.SessionSearchResult(
            session_id=session.id,
            game_type=session.game_type,
            mode=session.mode,
            creator_id=session.creator_id,
            participants_count=participants_count,
            is_active=session.is_active
        )
        results.append(session_data)
    
    return results

@app.post("/join_session", tags=["Sessions"])
def join_session(join_in: schemas.JoinSession, current_user: models.User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """
    Allows a user to join an existing session.
    """
    session = db.query(models.Session).filter(models.Session.id == join_in.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    if not session.is_active:
        raise HTTPException(status_code=400, detail="Session is not active.")
    
    # Check if user is already a participant
    participant = db.query(models.SessionParticipant).filter(
        models.SessionParticipant.session_id == join_in.session_id,
        models.SessionParticipant.user_id == current_user.id
    ).first()
    if participant:
        raise HTTPException(status_code=400, detail="User already in session.")
    
    # Add user as participant
    new_participant = models.SessionParticipant(
        id=str(uuid4()),
        session_id=join_in.session_id,
        user_id=current_user.id
    )
    db.add(new_participant)
    
    # If it's the first time the user joins, ensure current_turn is set appropriately
    if not session.current_turn:
        session.current_turn = current_user.id
    
    db.commit()
    
    return {"message": f"Joined session {join_in.session_id} successfully."}

@app.get("/get_completion_state", tags=["Games"])
def get_completion_state(session_id: str = Query(..., description="ID of the session"), current_user: models.User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """
    Retrieves the current state of the Completion Game, including the story and whose turn it is.
    """
    session = db.query(models.Session).filter(models.Session.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    if not session.is_active:
        raise HTTPException(status_code=400, detail="Session is not active.")
    
    # Check if user is a participant
    participant = db.query(models.SessionParticipant).filter(
        models.SessionParticipant.session_id == session_id,
        models.SessionParticipant.user_id == current_user.id
    ).first()
    if not participant:
        raise HTTPException(status_code=403, detail="User not part of this session.")
    
    # Retrieve story
    contributions = db.query(models.Contribution).filter(models.Contribution.session_id == session_id).order_by(models.Contribution.timestamp).all()
    story_data = [
        {
            "user_id": contrib.user_id,
            "content": contrib.content,
            "timestamp": contrib.timestamp
        }
        for contrib in contributions
    ]
    
    return {
        "story": story_data,
        "current_turn": session.current_turn
    }

@app.post("/completion_step", tags=["Games"])
def completion_step(session_id: str = Query(..., description="ID of the session"), content: str = Query(..., min_length=1, description="Content of the contribution"), current_user: models.User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """
    Allows a user to submit a contribution to the story during their turn.
    """
    session = db.query(models.Session).filter(models.Session.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    if not session.is_active:
        raise HTTPException(status_code=400, detail="Session is not active.")
    
    # Check if user is a participant
    participant = db.query(models.SessionParticipant).filter(
        models.SessionParticipant.session_id == session_id,
        models.SessionParticipant.user_id == current_user.id
    ).first()
    if not participant:
        raise HTTPException(status_code=403, detail="User not part of this session.")
    
    # Check if it's the user's turn
    if session.current_turn != current_user.id:
        raise HTTPException(status_code=403, detail="It's not your turn.")
    
    # Add contribution
    contribution = models.Contribution(
        id=str(uuid4()),
        session_id=session_id,
        user_id=current_user.id,
        content=content,
        timestamp=datetime.utcnow()
    )
    db.add(contribution)
    
    # Advance turn to the next participant
    participants = db.query(models.SessionParticipant).filter(models.SessionParticipant.session_id == session_id).order_by(models.SessionParticipant.id).all()
    participant_ids = [p.user_id for p in participants]
    try:
        current_index = participant_ids.index(current_user.id)
    except ValueError:
        current_index = 0  # Fallback
    next_index = (current_index + 1) % len(participant_ids)
    session.current_turn = participant_ids[next_index]
    
    db.commit()
    
    return {"message": "Contribution added successfully.", "next_turn": session.current_turn}

@app.post("/generate_story", tags=["Games"])
def generate_story(generate_in: schemas.GenerateStoryIn, current_user: models.User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """
    Triggers the LLM story enhancement for the session. Only the session creator can perform this action.
    """
    session = db.query(models.Session).filter(models.Session.id == generate_in.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    if session.creator_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the session creator can generate story enhancements.")
    if not session.is_active:
        raise HTTPException(status_code=400, detail="Session is not active.")
    
    # Placeholder for LLM story enhancement logic
    # Integrate with an actual LLM API (e.g., OpenAI GPT) here
    # For demonstration, we'll append a placeholder sentence
    enhanced_content = " [Story has been enhanced by the AI.]"
    contribution = models.Contribution(
        id=str(uuid4()),
        session_id=session.id,
        user_id="LLM_AI",
        content=enhanced_content,
        timestamp=datetime.utcnow()
    )
    db.add(contribution)
    
    # Advance turn to the next participant after AI contribution
    participants = db.query(models.SessionParticipant).filter(models.SessionParticipant.session_id == session.id).order_by(models.SessionParticipant.id).all()
    participant_ids = [p.user_id for p in participants]
    try:
        current_index = participant_ids.index(session.current_turn)
    except ValueError:
        current_index = 0  # Fallback
    next_index = (current_index + 1) % len(participant_ids)
    session.current_turn = participant_ids[next_index]
    
    db.commit()
    
    return {"message": "Story enhancement initiated and added to the story.", "next_turn": session.current_turn}

# -----------------------
# Search Endpoint
# -----------------------

@app.get("/search", response_model=schemas.SearchResults, tags=["Search"])
def search(
    query: str = Query(..., min_length=1, description="Search query string"),
    current_user: models.User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Searches for users and sessions based on the provided query string.
    
    - Searches users by username (case-insensitive substring match) or user ID (exact match).
    - Searches sessions by session ID (exact match or substring match).
    """
    # Normalize query for case-insensitive search
    normalized_query = query.lower()
    
    # Search Users
    users_query = db.query(models.User)
    matching_users = []
    
    if query:
        # Users with username containing the query (case-insensitive)
        users_with_username = users_query.filter(
            models.User.username.ilike(f"%{query}%")
        ).all()
        matching_users.extend([
            schemas.UserOut(
                id=user.id,
                username=user.username,
                is_guest=user.is_guest
            )
            for user in users_with_username
        ])
        
        # Guest users with exact user_id match
        guest_users = users_query.filter(
            models.User.is_guest == True,
            models.User.id == query
        ).all()
        matching_users.extend([
            schemas.UserOut(
                id=user.id,
                username=None,
                is_guest=user.is_guest
            )
            for user in guest_users
        ])
    
    # Remove duplicates
    unique_users = {user.id: user for user in matching_users}.values()
    
    # Search Sessions
    sessions_query = db.query(models.Session)
    matching_sessions = []
    
    if query:
        sessions_matching = sessions_query.filter(
            models.Session.id.ilike(f"%{query}%")
        ).all()
        for session in sessions_matching:
            participants_count = db.query(models.SessionParticipant).filter(
                models.SessionParticipant.session_id == session.id
            ).count()
            matching_sessions.append(
                schemas.SessionSearchResult(
                    session_id=session.id,
                    game_type=session.game_type,
                    mode=session.mode,
                    creator_id=session.creator_id,
                    participants_count=participants_count,
                    is_active=session.is_active
                )
            )
    
    return {
        "users": list(unique_users),
        "sessions": matching_sessions
    }

# -----------------------
# New Admin User Endpoints
# -----------------------

@app.post("/create_admin", response_model=schemas.UserOut, tags=["Admin"], dependencies=[Depends(get_current_active_user)])
def create_admin_user(
    user_in: schemas.UserCreate,
    current_user: models.User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Creates a new admin user.
    Only accessible by existing admin users.
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to create admin users.")
    
    # Check if username already exists
    existing_user = get_user_by_username(db, user_in.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered.")
    
    # Create new admin user
    user = models.User(
        id=str(uuid4()),
        username=user_in.username,
        hashed_password=get_password_hash(user_in.password),
        is_guest=False,
        is_admin=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return schemas.UserOut(
        id=user.id,
        username=user.username,
        is_guest=user.is_guest,
        is_admin=user.is_admin
    )

@app.post("/promote_user", response_model=schemas.UserOut, tags=["Admin"])
def promote_user_to_admin(
    user_id: str = Query(..., description="ID of the user to promote"),
    current_user: models.User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Promotes a regular user to an admin user.
    Only accessible by existing admin users.
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to promote users.")
    
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.is_admin:
        raise HTTPException(status_code=400, detail="User is already an admin.")
    
    user.is_admin = True
    db.commit()
    db.refresh(user)
    
    return schemas.UserOut(
        id=user.id,
        username=user.username,
        is_guest=user.is_guest,
        is_admin=user.is_admin
    )

@app.post("/demote_user", response_model=schemas.UserOut, tags=["Admin"])
def demote_admin_to_user(
    user_id: str = Query(..., description="ID of the admin user to demote"),
    current_user: models.User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Demotes an admin user to a regular user.
    Only accessible by existing admin users.
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to demote users.")
    
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if not user.is_admin:
        raise HTTPException(status_code=400, detail="User is not an admin.")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Admins cannot demote themselves.")
    
    user.is_admin = False
    db.commit()
    db.refresh(user)
    
    return schemas.UserOut(
        id=user.id,
        username=user.username,
        is_guest=user.is_guest,
        is_admin=user.is_admin
    )

# -----------------------
# Run the Application
# -----------------------

# To run the app, use the command:
# uvicorn main:app --reload

# This command should be executed in the backend/ directory.
