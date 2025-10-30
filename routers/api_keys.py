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
from db.database import get_db_connection

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

async def check_and_reset_quota(user_id: str, conn):
    """Check if quota needs reset and do it"""
    result = await conn.fetchrow(
        "SELECT * FROM api_quotas WHERE user_id = $1",
        user_id
    )
    
    if result and result['reset_date'] <= datetime.utcnow():
        await conn.execute(
            """UPDATE api_quotas 
               SET requests_used = 0, 
                   reset_date = NOW() + INTERVAL '1 month',
                   updated_at = NOW()
               WHERE user_id = $1""",
            user_id
        )

# Endpoints
@router.post("/keys", response_model=APIKeyCreatedResponse)
async def create_api_key(
    request: CreateAPIKeyRequest,
    authorization: str = Header(None)
):
    """Create a new API key for the authenticated user"""
    uid = _get_uid_from_token(authorization)
    
    conn = await get_db_connection()
    try:
        # Check if user has quota (create if not exists)
        quota = await conn.fetchrow(
            "SELECT * FROM api_quotas WHERE user_id = $1",
            uid
        )
        
        if not quota:
            # Create default quota for user
            await conn.execute(
                """INSERT INTO api_quotas (user_id, plan_type, monthly_requests)
                   VALUES ($1, 'free', 1000)""",
                uid
            )
        
        # Generate API key
        full_key, key_hash, key_prefix = generate_api_key(request.environment)
        
        # Calculate expiration
        expires_at = None
        if request.expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=request.expires_in_days)
        
        # Insert into database
        result = await conn.fetchrow(
            """INSERT INTO api_keys 
               (user_id, key_hash, key_prefix, name, environment, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING id, created_at""",
            uid, key_hash, key_prefix, request.name, request.environment, expires_at
        )
        
        return {
            "id": str(result['id']),
            "name": request.name,
            "key": full_key,  # Only time the full key is shown
            "key_prefix": key_prefix,
            "environment": request.environment,
            "created_at": result['created_at'].isoformat(),
            "message": "Store this key securely. You won't be able to see it again."
        }
        
    finally:
        await conn.close()

@router.get("/keys", response_model=List[APIKeyResponse])
async def list_api_keys(authorization: str = Header(None)):
    """List all API keys for the authenticated user"""
    uid = _get_uid_from_token(authorization)
    
    conn = await get_db_connection()
    try:
        results = await conn.fetch(
            """SELECT id, name, key_prefix, environment, permissions, 
                      created_at, last_used_at, expires_at, is_active
               FROM api_keys 
               WHERE user_id = $1
               ORDER BY created_at DESC""",
            uid
        )
        
        return [
            {
                "id": str(r['id']),
                "name": r['name'],
                "key_prefix": r['key_prefix'],
                "environment": r['environment'],
                "permissions": r['permissions'],
                "created_at": r['created_at'].isoformat(),
                "last_used_at": r['last_used_at'].isoformat() if r['last_used_at'] else None,
                "expires_at": r['expires_at'].isoformat() if r['expires_at'] else None,
                "is_active": r['is_active']
            }
            for r in results
        ]
        
    finally:
        await conn.close()

@router.patch("/keys/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    key_id: str,
    request: UpdateAPIKeyRequest,
    authorization: str = Header(None)
):
    """Update an API key (name or active status)"""
    uid = _get_uid_from_token(authorization)
    
    conn = await get_db_connection()
    try:
        # Verify ownership
        existing = await conn.fetchrow(
            "SELECT * FROM api_keys WHERE id = $1 AND user_id = $2",
            key_id, uid
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="API key not found")
        
        # Build update query
        updates = []
        params = []
        param_count = 1
        
        if request.name is not None:
            updates.append(f"name = ${param_count}")
            params.append(request.name)
            param_count += 1
        
        if request.is_active is not None:
            updates.append(f"is_active = ${param_count}")
            params.append(request.is_active)
            param_count += 1
        
        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")
        
        params.extend([key_id, uid])
        
        result = await conn.fetchrow(
            f"""UPDATE api_keys 
               SET {', '.join(updates)}
               WHERE id = ${param_count} AND user_id = ${param_count + 1}
               RETURNING id, name, key_prefix, environment, permissions, 
                         created_at, last_used_at, expires_at, is_active""",
            *params
        )
        
        return {
            "id": str(result['id']),
            "name": result['name'],
            "key_prefix": result['key_prefix'],
            "environment": result['environment'],
            "permissions": result['permissions'],
            "created_at": result['created_at'].isoformat(),
            "last_used_at": result['last_used_at'].isoformat() if result['last_used_at'] else None,
            "expires_at": result['expires_at'].isoformat() if result['expires_at'] else None,
            "is_active": result['is_active']
        }
        
    finally:
        await conn.close()

@router.delete("/keys/{key_id}")
async def delete_api_key(
    key_id: str,
    authorization: str = Header(None)
):
    """Delete (revoke) an API key"""
    uid = _get_uid_from_token(authorization)
    
    conn = await get_db_connection()
    try:
        result = await conn.execute(
            "DELETE FROM api_keys WHERE id = $1 AND user_id = $2",
            key_id, uid
        )
        
        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="API key not found")
        
        return {"message": "API key deleted successfully"}
        
    finally:
        await conn.close()

@router.get("/usage", response_model=APIUsageStats)
async def get_api_usage_stats(authorization: str = Header(None)):
    """Get API usage statistics and quota information"""
    uid = _get_uid_from_token(authorization)
    
    conn = await get_db_connection()
    try:
        # Check and reset quota if needed
        await check_and_reset_quota(uid, conn)
        
        # Get quota info
        quota = await conn.fetchrow(
            "SELECT * FROM api_quotas WHERE user_id = $1",
            uid
        )
        
        if not quota:
            # Create default quota
            await conn.execute(
                """INSERT INTO api_quotas (user_id, plan_type, monthly_requests)
                   VALUES ($1, 'free', 1000)""",
                uid
            )
            quota = await conn.fetchrow(
                "SELECT * FROM api_quotas WHERE user_id = $1",
                uid
            )
        
        # Get total requests
        total_requests = await conn.fetchval(
            """SELECT COUNT(*) FROM api_usage_logs 
               WHERE api_key_id IN (
                   SELECT id FROM api_keys WHERE user_id = $1
               )""",
            uid
        )
        
        # Get requests today
        requests_today = await conn.fetchval(
            """SELECT COUNT(*) FROM api_usage_logs 
               WHERE api_key_id IN (
                   SELECT id FROM api_keys WHERE user_id = $1
               )
               AND created_at >= CURRENT_DATE""",
            uid
        )
        
        # Get top endpoints
        top_endpoints_raw = await conn.fetch(
            """SELECT endpoint, COUNT(*) as count
               FROM api_usage_logs 
               WHERE api_key_id IN (
                   SELECT id FROM api_keys WHERE user_id = $1
               )
               AND created_at >= NOW() - INTERVAL '30 days'
               GROUP BY endpoint
               ORDER BY count DESC
               LIMIT 5""",
            uid
        )
        
        top_endpoints = [
            {"endpoint": r['endpoint'], "count": r['count']}
            for r in top_endpoints_raw
        ]
        
        return {
            "total_requests": total_requests or 0,
            "requests_today": requests_today or 0,
            "quota_limit": quota['monthly_requests'],
            "quota_used": quota['requests_used'],
            "quota_remaining": max(0, quota['monthly_requests'] - quota['requests_used']),
            "reset_date": quota['reset_date'].isoformat(),
            "top_endpoints": top_endpoints
        }
        
    finally:
        await conn.close()

@router.get("/logs")
async def get_api_logs(
    limit: int = 100,
    offset: int = 0,
    authorization: str = Header(None)
):
    """Get recent API usage logs"""
    uid = _get_uid_from_token(authorization)
    
    conn = await get_db_connection()
    try:
        logs = await conn.fetch(
            """SELECT l.*, k.name as key_name, k.key_prefix
               FROM api_usage_logs l
               JOIN api_keys k ON l.api_key_id = k.id
               WHERE k.user_id = $1
               ORDER BY l.created_at DESC
               LIMIT $2 OFFSET $3""",
            uid, limit, offset
        )
        
        return [
            {
                "id": str(log['id']),
                "key_name": log['key_name'],
                "key_prefix": log['key_prefix'],
                "endpoint": log['endpoint'],
                "method": log['method'],
                "status_code": log['status_code'],
                "response_time_ms": log['response_time_ms'],
                "ip_address": str(log['ip_address']) if log['ip_address'] else None,
                "error_message": log['error_message'],
                "created_at": log['created_at'].isoformat()
            }
            for log in logs
        ]
        
    finally:
        await conn.close()
