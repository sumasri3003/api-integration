from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from dotenv import load_dotenv
import mysql.connector
import os
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

# Load environment variables
# ----------------------
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "mysecretkey")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "12345")
DB_NAME = os.getenv("DB_NAME", "version")

# FastAPI App
# ----------------------
app = FastAPI(title="JWT + RBAC Demo")

bearer_scheme = HTTPBearer(auto_error=False)

# Pydantic Models
# ----------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: Optional[datetime]

class TokenData(BaseModel):
    username: Optional[str] = None
    roles: List[str] = []

class User(BaseModel):
    username: str
    email: Optional[str] = None
    roles: List[str] = []

# Database Connection
# ----------------------
def get_conn():
    try:
        return mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Database connection error: {e}")

# Helper Functions
# ----------------------
def verify_password(plain_password: str, stored_password: str) -> bool:
    return plain_password == stored_password

def get_user_from_db(username: str) -> Optional[dict]:
    conn = get_conn()
    cursor = conn.cursor(dictionary=True)
    # Removed full_name because your table does not have it
    cursor.execute("SELECT username, email, password FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        conn.close()
        return None
    cursor.execute("SELECT role_name FROM user_roles WHERE username = %s", (username,))
    roles = [row["role_name"] for row in cursor.fetchall()]
    user["roles"] = roles
    cursor.close()
    conn.close()
    return user

def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = get_user_from_db(username)
    if not user or not verify_password(password, user["password"]):
        return None
    return user

def create_access_token(*, data: dict, expires_delta: Optional[timedelta] = None) -> Tuple[str, datetime]:
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": now})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt, expire

def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: Optional[str] = payload.get("sub")
        roles = payload.get("roles") or []
        return TokenData(username=username, roles=roles)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

# Dependencies
# ----------------------
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    token_data = decode_token(token)
    user = get_user_from_db(token_data.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return User(
        username=user["username"],
        email=user.get("email"),
        roles=user.get("roles", [])
    )

def require_role(role: str):
    def dependency(user: User = Depends(get_current_user)):
        if role not in (user.roles or []):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden - missing role")
        return user
    return dependency

# Routes
# ----------------------
@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token_payload = {"sub": user["username"], "roles": user.get("roles", [])}
    token, expires_at = create_access_token(data=token_payload)
    return Token(access_token=token, expires_at=expires_at)

@app.get("/protected")
async def protected_route(current_user: User = Depends(get_current_user)):
    return {"msg": f"Hello {current_user.username}, you are authenticated.", "roles": current_user.roles}

@app.get("/admin")
async def admin_route(current_user: User = Depends(require_role("admin"))):
    return {"msg": f"Welcome admin {current_user.username}. You may manage resources."}

@app.get("/debug/users")
async def list_users():
    conn = get_conn()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT username, email, password FROM users")
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return users