
import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List
import logging
import os
from datetime import timedelta

# Use absolute imports
import models
import schemas
import database
import security

# Correctly use database.Base to create tables
database.Base.metadata.create_all(bind=database.engine)

# --- App Initialization ---
app = FastAPI(
    title="Vyapaars Backend",
    description="Backend for the Vyapaars offline-first POS application.",
    version="1.0.0",
)

logger = logging.getLogger(__name__)

# --- API Endpoints ---

@app.post("/api/v1/register", response_model=schemas.User, status_code=201)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = security.get_user(db, phone=user.phone)
    if db_user:
        raise HTTPException(status_code=400, detail="Phone number already registered")
    return security.create_user(db=db, user=user)

@app.post("/api/v1/login", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = security.authenticate_user(db, phone=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect phone number or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.phone}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/v1/sync/batch", response_model=schemas.SyncResponse)
def sync_batch_data(batch: schemas.SyncBatch, current_user: models.User = Depends(security.get_current_user), db: Session = Depends(database.get_db)):
    logger.info(f"Sync batch from user: {current_user.phone} on device: {batch.device_id}")
    logger.info(f"SYNC DATA: {batch.dict()}")
    
    processed_actions = {}
    for action_data in batch.client_actions:
        # Check if action has already been processed
        db_action = db.query(models.UserAction).filter(models.UserAction.client_id == str(action_data.client_id)).first()
        if db_action:
            continue

        # Create and save the user action
        new_action = models.UserAction(
            user_id=current_user.id,
            client_id=str(action_data.client_id),
            type=action_data.type,
            payload=action_data.payload,
            timestamp=action_data.timestamp
        )
        db.add(new_action)
        
        # Here you would add logic to actually process the payload, e.g., update inventory
        # For now, we just log it.
        logger.info(f"Processing action {new_action.client_id} of type {new_action.type}")

        processed_actions[action_data.client_id] = {"status": "processed", "server_id": str(new_action.id)}

    db.commit()
    return schemas.SyncResponse(status="ok", processed_actions=processed_actions)

@app.get("/users/me/", response_model=schemas.User)
async def read_users_me(current_user: models.User = Depends(security.get_current_user)):
    return current_user

if __name__ == "__main__":
    # Use the PORT environment variable provided by Render
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
