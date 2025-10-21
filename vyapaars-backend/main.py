
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
    version="0.4.1", # Version bump for password fix
)

# --- Security & JWT Configuration (Phase 6) ---
SECRET_KEY = os.environ.get("SECRET_KEY", "a_very_secret_key_for_development_only_change_it")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")

# --- Security Helper Functions ---
def get_password_hash(password: str) -> str:
    """
    Hashes a plain-text password using bcrypt.
    It also truncates the password to 72 bytes to prevent errors with bcrypt.
    """
    # Truncate password to 72 bytes to prevent bcrypt ValueError
    password_bytes = password.encode('utf-8')
    return pwd_context.hash(password_bytes[:72])

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a hashed one.
    It also truncates the plain password to 72 bytes for verification.
    """
    password_bytes = plain_password.encode('utf-8')
    return pwd_context.verify(password_bytes[:72], hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Creates a new JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- In-Memory Database (for MVP / Render's free tier) ---
USERS_DB: Dict[str, dict] = {}
VERIFICATION_DB: Dict[str, str] = {}
USER_ACTIONS_DB: Dict[str, List[Dict]] = {}
PROCESSED_ACTIONS_DB: Dict[str, dict] = {}
ASSET_METADATA_DB = {
    "products.csv": {"version": "v1.0.0", "checksum": "initial", "size": 0, "notes": "Initial list."}
}
FEATURE_FLAGS_DB = {
    "show_new_promo": {"enabled": False},
    "enable_dark_mode_toggle": {"enabled": True, "min_version": "1.0.0"}
}
ASSET_STORAGE_PATH = "assets"
os.makedirs(ASSET_STORAGE_PATH, exist_ok=True)

# --- Pydantic Schemas ---
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

# --- Dependency for User Authentication ---
async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        phone: str = payload.get("sub")
        if phone is None or phone not in USERS_DB:
            raise credentials_exception
        return phone
    except JWTError:
        raise credentials_exception

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"status": "ok", "message": "Vyapaars Backend is running."}

@app.post("/api/v1/register", status_code=201)
def register_user(user: UserCreate):
    if user.phone in USERS_DB: raise HTTPException(400, "Phone number already registered")
    hashed_password = get_password_hash(user.password)
    USERS_DB[user.phone] = {"full_name": user.full_name, "password": hashed_password, "is_verified": False}
    otp = ''.join(random.choices(string.digits, k=6))
    VERIFICATION_DB[user.phone] = otp
    logger.info(f"[TESTING] Verification OTP for {user.phone}: {otp}")
    return {"message": "Registration successful. Please verify.", "test_otp": otp}

@app.post("/api/v1/verify")
def verify_user(data: VerificationData):
    if VERIFICATION_DB.get(data.phone) != data.code: raise HTTPException(400, "Invalid code")
    USERS_DB[data.phone]["is_verified"] = True
    del VERIFICATION_DB[data.phone]
    return {"message": "Verification successful."}

@app.post("/api/v1/login", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = USERS_DB.get(form_data.username)
    if not user or not user["is_verified"] or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect phone/password")
    token = create_access_token(data={"sub": form_data.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

# --- Core Sync Endpoint ---
@app.post("/api/v1/sync/batch", response_model=SyncResponse)
def sync_batch_data(batch: SyncBatch, current_user: str = Depends(get_current_user)):
    logger.info(f"Sync batch from user: {current_user} on device: {batch.device_id}")
    processed = {}
    if current_user not in USER_ACTIONS_DB: USER_ACTIONS_DB[current_user] = []

    for action in batch.client_actions:
        if str(action.client_id) in PROCESSED_ACTIONS_DB: continue
        USER_ACTIONS_DB[current_user].append(action.dict())
        logger.info(f"User {current_user} synced action {action.client_id} ({action.type}).")
        server_id = str(uuid.uuid4())
        PROCESSED_ACTIONS_DB[str(action.client_id)] = {"server_id": server_id, "status": "processed"}
        processed[action.client_id] = {"status": "processed", "server_id": server_id}
    
    return SyncResponse(status="ok", processed_actions=processed)

# --- Asset Pipeline ---
@app.get("/api/v1/assets/products/meta")
def get_products_meta(current_user: str = Depends(get_current_user)):
    return ASSET_METADATA_DB["products.csv"]

@app.get("/api/v1/assets/products.csv")
def download_products_csv(current_user: str = Depends(get_current_user)):
    file_path = os.path.join(ASSET_STORAGE_PATH, "products.csv")
    if not os.path.exists(file_path): raise HTTPException(404, "products.csv not found.")
    return FileResponse(path=file_path, media_type='text/csv', filename="products.csv")

@app.post("/api/v1/admin/assets/upload/products")
async def upload_products_csv(file: UploadFile = File(...)):
    file_path = os.path.join(ASSET_STORAGE_PATH, "products.csv")
    file_content = await file.read()
    
    with open(file_path, "wb") as buffer:
        buffer.write(file_content)
    
    checksum = hashlib.sha256(file_content).hexdigest()
    meta = ASSET_METADATA_DB["products.csv"]
    meta["size"] = len(file_content)
    meta["version"] = f"v{datetime.utcnow().timestamp():.0f}"
    meta["checksum"] = checksum
    logger.info(f"New products.csv uploaded. Version: {meta['version']}")
    return {"status": "ok", "new_metadata": meta}

# --- Remote Feature Flags ---
@app.get("/api/v1/config/flags")
def get_feature_flags(current_user: str = Depends(get_current_user)):
    return FEATURE_FLAGS_DB

@app.put("/api/v1/admin/config/flags")
def update_feature_flags(flags: Dict[str, Any]):
    FEATURE_FLAGS_DB.update(flags)
    logger.info(f"Feature flags updated: {flags}")
    return {"status": "ok", "new_flags": FEATURE_FLAGS_DB}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
