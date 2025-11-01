"""
API Key Management Router for Developer Platform
Handles creation, listing, revocation, and management of API keys
"""
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional, List
import hashlib
import secrets
import os
from datetime import datetime, timedelta
from db.database import async_session_maker
from sqlalchemy import text

router = APIRouter(prefix="/api/developer", tags=["API Keys"])

# Pydantic Models
class CreateAPIKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Name for the API key")
    environment: str = Field(default="production", pattern="^(production|test)$")
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365, description="Days until expiration")

class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    environment: str
    permissions: dict
    created_at: str
    last_used_at: Optional[str]
    expires_at: Optional[str]
    is_active: bool

class APIKeyCreatedResponse(BaseModel):
    id: str
    name: str
    key: str  # Full key only shown once
    key_prefix: str
    environment: str
    created_at: str
    message: str = "Store this key securely. You won't be able to see it again."

class APIUsageStats(BaseModel):
    total_requests: int
    requests_today: int
    quota_limit: int
    quota_used: int
    quota_remaining: int
    reset_date: str
    top_endpoints: List[dict]

class UpdateAPIKeyRequest(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None

# Helper Functions
def _get_uid_from_token(authorization: str = Header(None)) -> str:
    """Extract and verify Firebase token, return UID"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    try:
        import firebase_admin.auth as firebase_auth
        decoded_token = firebase_auth.verify_id_token(token)
        return decoded_token["uid"]
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

def generate_api_key(environment: str = "production") -> tuple[str, str, str]:
    """
    Generate a secure API key
    Returns: (full_key, key_hash, key_prefix)
    """
    # Generate random key: ce_live_xxx or ce_test_xxx
    prefix = "ce_live" if environment == "production" else "ce_test"
    random_part = secrets.token_urlsafe(32)  # 32 bytes = 43 chars in base64
    full_key = f"{prefix}_{random_part}"
    
    # Hash the key for storage (SHA256)
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    
    # Store first 12 chars as prefix for display
    key_prefix = full_key[:20] + "..."
    
    return full_key, key_hash, key_prefix

async def check_and_reset_quota(user_id: str, session):
    """Check if quota needs reset and do it"""
    result = await session.execute(
        text("SELECT user_id, requests_used, monthly_requests, reset_date FROM api_quotas WHERE user_id = :user_id"),
        {"user_id": user_id}
    )
    row = result.fetchone()
    
    if row and row.reset_date <= datetime.utcnow():
        await session.execute(
            text("""UPDATE api_quotas 
               SET requests_used = 0, 
                   reset_date = NOW() + INTERVAL '1 month',
                   updated_at = NOW()
               WHERE user_id = :user_id"""),
            {"user_id": user_id}
        )
        await session.commit()

# Endpoints
@router.post("/keys", response_model=APIKeyCreatedResponse)
async def create_api_key(
    request: CreateAPIKeyRequest,
    authorization: str = Header(None)
):
    """Create a new API key for the authenticated user"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        # Check if user has quota (create if not exists)
        result = await session.execute(
            text("SELECT * FROM api_quotas WHERE user_id = :uid"),
            {"uid": uid}
        )
        quota = result.fetchone()
        
        if not quota:
            # Create default quota for user
            await session.execute(
                text("""INSERT INTO api_quotas (user_id, plan_type, monthly_requests)
                       VALUES (:uid, 'free', 1000)"""),
                {"uid": uid}
            )
            await session.commit()
        
        # Generate API key
        full_key, key_hash, key_prefix = generate_api_key(request.environment)
        
        # Calculate expiration
        expires_at = None
        if request.expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=request.expires_in_days)
        
        # Insert into database
        result = await session.execute(
            text("""INSERT INTO api_keys 
               (user_id, key_hash, key_prefix, name, environment, expires_at)
               VALUES (:uid, :key_hash, :key_prefix, :name, :environment, :expires_at)
               RETURNING id, created_at"""),
            {"uid": uid, "key_hash": key_hash, "key_prefix": key_prefix, 
             "name": request.name, "environment": request.environment, "expires_at": expires_at}
        )
        row = result.fetchone()
        await session.commit()
        
        return {
            "id": str(row[0]),
            "name": request.name,
            "key": full_key,  # Only time the full key is shown
            "key_prefix": key_prefix,
            "environment": request.environment,
            "created_at": row[1].isoformat(),
            "message": "Store this key securely. You won't be able to see it again."
        }

@router.get("/keys", response_model=List[APIKeyResponse])
async def list_api_keys(authorization: str = Header(None)):
    """List all API keys for the authenticated user"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""SELECT id, name, key_prefix, environment, permissions, 
                          created_at, last_used_at, expires_at, is_active
                   FROM api_keys 
                   WHERE user_id = :uid
                   ORDER BY created_at DESC"""),
            {"uid": uid}
        )
        results = result.fetchall()
        
        return [
            {
                "id": str(r[0]),
                "name": r[1],
                "key_prefix": r[2],
                "environment": r[3],
                "permissions": r[4],
                "created_at": r[5].isoformat(),
                "last_used_at": r[6].isoformat() if r[6] else None,
                "expires_at": r[7].isoformat() if r[7] else None,
                "is_active": r[8]
            }
            for r in results
        ]

@router.patch("/keys/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    key_id: str,
    request: UpdateAPIKeyRequest,
    authorization: str = Header(None)
):
    """Update an API key (name or active status)"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        # Verify ownership
        result = await session.execute(
            text("SELECT * FROM api_keys WHERE id = :key_id AND user_id = :uid"),
            {"key_id": key_id, "uid": uid}
        )
        existing = result.fetchone()
        
        if not existing:
            raise HTTPException(status_code=404, detail="API key not found")
        
        # Build update query
        updates = []
        params = {"key_id": key_id, "uid": uid}
        
        if request.name is not None:
            updates.append("name = :name")
            params["name"] = request.name
        
        if request.is_active is not None:
            updates.append("is_active = :is_active")
            params["is_active"] = request.is_active
        
        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")
        
        result = await session.execute(
            text(f"""UPDATE api_keys 
               SET {', '.join(updates)}
               WHERE id = :key_id AND user_id = :uid
               RETURNING id, name, key_prefix, environment, permissions, 
                         created_at, last_used_at, expires_at, is_active"""),
            params
        )
        row = result.fetchone()
        await session.commit()
        
        return {
            "id": str(row[0]),
            "name": row[1],
            "key_prefix": row[2],
            "environment": row[3],
            "permissions": row[4],
            "created_at": row[5].isoformat(),
            "last_used_at": row[6].isoformat() if row[6] else None,
            "expires_at": row[7].isoformat() if row[7] else None,
            "is_active": row[8]
        }

@router.delete("/keys/{key_id}")
async def delete_api_key(
    key_id: str,
    authorization: str = Header(None)
):
    """Delete (revoke) an API key"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("DELETE FROM api_keys WHERE id = :key_id AND user_id = :uid"),
            {"key_id": key_id, "uid": uid}
        )
        await session.commit()
        
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="API key not found")
        
        return {"message": "API key deleted successfully"}

@router.get("/usage", response_model=APIUsageStats)
async def get_api_usage_stats(authorization: str = Header(None)):
    """Get API usage statistics and quota information"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        # Check and reset quota if needed
        await check_and_reset_quota(uid, session)
        
        # Get quota info
        result = await session.execute(
            text("SELECT * FROM api_quotas WHERE user_id = :uid"),
            {"uid": uid}
        )
        quota = result.fetchone()
        
        if not quota:
            # Create default quota
            await session.execute(
                text("""INSERT INTO api_quotas (user_id, plan_type, monthly_requests)
                       VALUES (:uid, 'free', 1000)"""),
                {"uid": uid}
            )
            await session.commit()
            result = await session.execute(
                text("SELECT * FROM api_quotas WHERE user_id = :uid"),
                {"uid": uid}
            )
            quota = result.fetchone()
        
        # Get total requests
        result = await session.execute(
            text("""SELECT COUNT(*) FROM api_usage_logs 
               WHERE api_key_id IN (
                   SELECT id FROM api_keys WHERE user_id = :uid
               )"""),
            {"uid": uid}
        )
        total_requests = result.scalar()
        
        # Get requests today
        result = await session.execute(
            text("""SELECT COUNT(*) FROM api_usage_logs 
               WHERE api_key_id IN (
                   SELECT id FROM api_keys WHERE user_id = :uid
               )
               AND created_at >= CURRENT_DATE"""),
            {"uid": uid}
        )
        requests_today = result.scalar()
        
        # Get top endpoints
        result = await session.execute(
            text("""SELECT endpoint, COUNT(*) as count
               FROM api_usage_logs 
               WHERE api_key_id IN (
                   SELECT id FROM api_keys WHERE user_id = :uid
               )
               AND created_at >= NOW() - INTERVAL '30 days'
               GROUP BY endpoint
               ORDER BY count DESC
               LIMIT 5"""),
            {"uid": uid}
        )
        top_endpoints_raw = result.fetchall()
        
        top_endpoints = [
            {"endpoint": r[0], "count": r[1]}
            for r in top_endpoints_raw
        ]
        
        return {
            "total_requests": total_requests or 0,
            "requests_today": requests_today or 0,
            "quota_limit": quota[2],  # monthly_requests
            "quota_used": quota[1],  # requests_used
            "quota_remaining": max(0, quota[2] - quota[1]),
            "reset_date": quota[3].isoformat(),  # reset_date
            "top_endpoints": top_endpoints
        }

@router.get("/logs")
async def get_api_logs(
    limit: int = 100,
    offset: int = 0,
    authorization: str = Header(None)
):
    """Get recent API usage logs"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""SELECT l.*, k.name as key_name, k.key_prefix
               FROM api_usage_logs l
               JOIN api_keys k ON l.api_key_id = k.id
               WHERE k.user_id = :uid
               ORDER BY l.created_at DESC
               LIMIT :limit OFFSET :offset"""),
            {"uid": uid, "limit": limit, "offset": offset}
        )
        logs = result.fetchall()
        
        return [
            {
                "id": str(log[0]),
                "key_name": log[9],  # key_name from join
                "key_prefix": log[10],  # key_prefix from join
                "endpoint": log[2],
                "method": log[3],
                "status_code": log[4],
                "response_time_ms": log[5],
                "ip_address": str(log[6]) if log[6] else None,
                "error_message": log[8],
                "created_at": log[1].isoformat()
            }
            for log in logs
        ]
