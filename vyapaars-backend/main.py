
import uvicorn
from fastapi import FastAPI, HTTPException, Body, Depends, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import uuid
import logging
import os
import random
import string
import hashlib
from datetime import datetime, timedelta

# Security libraries for password hashing and JWT
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- Configuration & Basic Setup ---
# Standard Python logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize the FastAPI application
app = FastAPI(
    title="Vyapaars Backend",
    description="Backend for the Vyapaars offline-first POS application.",
    version="0.4.0", # Version bump for new comments and README
)

# --- Security & JWT Configuration (Phase 6) ---
# This key should be stored securely as an environment variable in production.
# For Render, you will set this in the "Environment" tab.
SECRET_KEY = os.environ.get("SECRET_KEY", "a_very_secret_key_for_development_only_change_it")
ALGORITHM = "HS256" # Standard algorithm for JWT signing
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # Tokens will be valid for 1 week

# Password hashing setup using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme definition. `tokenUrl` points to our login endpoint.
# FastAPI uses this to know where clients should go to get a token.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")

# --- Security Helper Functions ---
def get_password_hash(password: str) -> str:
    """Hashes a plain-text password using bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain-text password against a hashed one."""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Creates a new JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- In-Memory Database (for MVP / Render's free tier) ---
# In a larger-scale production environment, these would be replaced with Postgres tables.
USERS_DB: Dict[str, dict] = {} # Stores user profiles, keyed by phone number
VERIFICATION_DB: Dict[str, str] = {} # Stores OTP codes for phone verification
USER_ACTIONS_DB: Dict[str, List[Dict]] = {} # Stores all synced actions, keyed by user phone number
PROCESSED_ACTIONS_DB: Dict[str, dict] = {} # Global store for idempotency keys to prevent duplicate processing
ASSET_METADATA_DB = {
    "products.csv": {"version": "v1.0.0", "checksum": "initial", "size": 0, "notes": "Initial list."}
}
FEATURE_FLAGS_DB = {
    "show_new_promo": {"enabled": False},
    "enable_dark_mode_toggle": {"enabled": True, "min_version": "1.0.0"}
}
ASSET_STORAGE_PATH = "assets" # Directory to store uploaded CSV files
os.makedirs(ASSET_STORAGE_PATH, exist_ok=True)

# --- Pydantic Schemas (Defines the shape of API data) ---
# These models provide automatic data validation for incoming requests.
class UserCreate(BaseModel):
    phone: str
    password: str
    full_name: str

class VerificationData(BaseModel):
    phone: str
    code: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ClientAction(BaseModel):
    """A single action from the app, designed for the sync batch."""
    client_id: uuid.UUID
    type: str # e.g., 'sale', 'inventory_update'
    payload: Dict[str, Any]
    timestamp: datetime # Timestamp from the app when the action occurred

class SyncBatch(BaseModel):
    """A batch of actions sent by the app's WorkManager."""
    device_id: str
    app_version: str
    client_actions: List[ClientAction]

class SyncResponse(BaseModel):
    status: str
    processed_actions: Dict[uuid.UUID, Dict[str, Any]]

# --- Dependency for User Authentication ---
async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """Decodes the JWT token from the request header and returns the user's phone number."""
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        phone: str = payload.get("sub") # 'sub' is the standard JWT claim for subject (our user's phone)
        if phone is None or phone not in USERS_DB:
            raise credentials_exception
        return phone
    except JWTError:
        raise credentials_exception

# --- API Endpoints ---

@app.get("/")
def read_root():
    """A simple health-check endpoint to confirm the server is running."""
    return {"status": "ok", "message": "Vyapaars Backend is running."}

# --- User Authentication Endpoints (Phase 1) ---
@app.post("/api/v1/register", status_code=201)
def register_user(user: UserCreate):
    """Handles new user registration."""
    if user.phone in USERS_DB: raise HTTPException(400, "Phone number already registered")
    hashed_password = get_password_hash(user.password)
    USERS_DB[user.phone] = {"full_name": user.full_name, "password": hashed_password, "is_verified": False}
    otp = ''.join(random.choices(string.digits, k=6))
    VERIFICATION_DB[user.phone] = otp
    logger.info(f"[TESTING] Verification OTP for {user.phone}: {otp}")
    return {"message": "Registration successful. Please verify.", "test_otp": otp}

@app.post("/api/v1/verify")
def verify_user(data: VerificationData):
    """Verifies a user's phone number using the OTP."""
    if VERIFICATION_DB.get(data.phone) != data.code: raise HTTPException(400, "Invalid code")
    USERS_DB[data.phone]["is_verified"] = True
    del VERIFICATION_DB[data.phone]
    return {"message": "Verification successful."}

@app.post("/api/v1/login", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Handles user login and issues a JWT access token."""
    user = USERS_DB.get(form_data.username) # The 'username' field from the form is the phone number
    if not user or not user["is_verified"] or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect phone/password")
    token = create_access_token(data={"sub": form_data.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

# --- Core Sync Endpoint (User-Wise) ---
@app.post("/api/v1/sync/batch", response_model=SyncResponse)
def sync_batch_data(batch: SyncBatch, current_user: str = Depends(get_current_user)):
    """Processes a batch of offline actions for the currently authenticated user."""
    logger.info(f"Sync batch from user: {current_user} on device: {batch.device_id}")
    processed = {}
    if current_user not in USER_ACTIONS_DB: USER_ACTIONS_DB[current_user] = []

    for action in batch.client_actions:
        # Idempotency check: if we've seen this client_id before, skip it.
        if str(action.client_id) in PROCESSED_ACTIONS_DB: continue
        
        # Store the action under the specific user's record.
        # This is where sales, inventory changes, etc., are saved.
        USER_ACTIONS_DB[current_user].append(action.dict())
        logger.info(f"User {current_user} synced action {action.client_id} ({action.type}).")

        # Mark as processed globally to prevent any user from re-processing.
        server_id = str(uuid.uuid4())
        PROCESSED_ACTIONS_DB[str(action.client_id)] = {"server_id": server_id, "status": "processed"}
        processed[action.client_id] = {"status": "processed", "server_id": server_id}
    
    return SyncResponse(status="ok", processed_actions=processed)

# --- Asset Pipeline (Phase 2 & 4) ---
@app.get("/api/v1/assets/products/meta")
def get_products_meta(current_user: str = Depends(get_current_user)):
    """Returns metadata about the latest product CSV file."""
    return ASSET_METADATA_DB["products.csv"]

@app.get("/api/v1/assets/products.csv")
def download_products_csv(current_user: str = Depends(get_current_user)):
    """Allows the authenticated user to download the product CSV file."""
    file_path = os.path.join(ASSET_STORAGE_PATH, "products.csv")
    if not os.path.exists(file_path): raise HTTPException(404, "products.csv not found.")
    return FileResponse(path=file_path, media_type='text/csv', filename="products.csv")

@app.post("/api/v1/admin/assets/upload/products")
async def upload_products_csv(file: UploadFile = File(...)):
    """An admin endpoint to upload a new products.csv."""
    file_path = os.path.join(ASSET_STORAGE_PATH, "products.csv")
    file_content = await file.read()
    
    with open(file_path, "wb") as buffer:
        buffer.write(file_content)
    
    # Calculate a SHA256 checksum for data integrity.
    checksum = hashlib.sha256(file_content).hexdigest()
    
    # Update the asset metadata.
    meta = ASSET_METADATA_DB["products.csv"]
    meta["size"] = len(file_content)
    meta["version"] = f"v{datetime.utcnow().timestamp():.0f}"
    meta["checksum"] = checksum
    logger.info(f"New products.csv uploaded. Version: {meta['version']}")
    return {"status": "ok", "new_metadata": meta}

# --- Remote Feature Flags (Phase 3) ---
@app.get("/api/v1/config/flags")
def get_feature_flags(current_user: str = Depends(get_current_user)):
    """Returns the current feature flag settings for the app."""
    return FEATURE_FLAGS_DB

@app.put("/api/v1/admin/config/flags")
def update_feature_flags(flags: Dict[str, Any]):
    """An admin endpoint to update feature flags without a new deploy."""
    FEATURE_FLAGS_DB.update(flags)
    logger.info(f"Feature flags updated: {flags}")
    return {"status": "ok", "new_flags": FEATURE_FLAGS_DB}

# --- Main Entry Point ---
if __name__ == "__main__":
    # This block allows running the server directly with `python main.py`
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
