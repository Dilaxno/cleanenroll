"""
API Key Authentication Middleware
Validates API keys and tracks usage
"""
from fastapi import HTTPException, Header, Request
from typing import Optional
import hashlib
from datetime import datetime
from db.database import get_db_connection
import time

async def verify_api_key(api_key: str = Header(None, alias="X-API-Key")) -> dict:
    """
    Verify API key and return associated data
    Raises HTTPException if invalid
    """
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Include 'X-API-Key' header.",
            headers={"WWW-Authenticate": "ApiKey"}
        )
    
    # Validate format
    if not api_key.startswith(("ce_live_", "ce_test_")):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key format"
        )
    
    # Hash the key to compare with stored hash
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    conn = await get_db_connection()
    try:
        # Look up key in database
        result = await conn.fetchrow(
            """SELECT k.*, u.email, u.uid, q.requests_used, q.monthly_requests, q.reset_date
               FROM api_keys k
               JOIN users u ON k.user_id = u.uid
               LEFT JOIN api_quotas q ON k.user_id = q.user_id
               WHERE k.key_hash = $1 AND k.is_active = TRUE""",
            key_hash
        )
        
        if not result:
            raise HTTPException(
                status_code=401,
                detail="Invalid or inactive API key"
            )
        
        # Check if expired
        if result['expires_at'] and result['expires_at'] < datetime.utcnow():
            raise HTTPException(
                status_code=401,
                detail="API key has expired"
            )
        
        # Check quota
        if result['reset_date'] and result['reset_date'] <= datetime.utcnow():
            # Reset quota
            await conn.execute(
                """UPDATE api_quotas 
                   SET requests_used = 0, 
                       reset_date = NOW() + INTERVAL '1 month',
                       updated_at = NOW()
                   WHERE user_id = $1""",
                result['user_id']
            )
            requests_used = 0
        else:
            requests_used = result['requests_used'] or 0
        
        monthly_requests = result['monthly_requests'] or 1000
        
        if requests_used >= monthly_requests:
            raise HTTPException(
                status_code=429,
                detail=f"API quota exceeded. Limit: {monthly_requests}/month. Resets: {result['reset_date']}"
            )
        
        # Update last_used_at
        await conn.execute(
            "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
            result['id']
        )
        
        # Increment quota counter
        await conn.execute(
            "UPDATE api_quotas SET requests_used = requests_used + 1 WHERE user_id = $1",
            result['user_id']
        )
        
        return {
            "api_key_id": str(result['id']),
            "user_id": result['user_id'],
            "email": result['email'],
            "environment": result['environment'],
            "permissions": result['permissions'],
            "quota_used": requests_used + 1,
            "quota_limit": monthly_requests
        }
        
    finally:
        await conn.close()

async def log_api_request(
    api_key_id: str,
    endpoint: str,
    method: str,
    status_code: int,
    response_time_ms: int,
    request: Request,
    error_message: Optional[str] = None
):
    """Log API request for analytics"""
    conn = await get_db_connection()
    try:
        # Get client IP
        ip_address = request.client.host if request.client else None
        
        # Get user agent
        user_agent = request.headers.get("user-agent")
        
        await conn.execute(
            """INSERT INTO api_usage_logs 
               (api_key_id, endpoint, method, status_code, response_time_ms, 
                ip_address, user_agent, error_message)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
            api_key_id, endpoint, method, status_code, response_time_ms,
            ip_address, user_agent, error_message
        )
    finally:
        await conn.close()

class APIKeyDependency:
    """Dependency class for API key authentication with automatic logging"""
    
    def __init__(self):
        self.start_time = None
    
    async def __call__(self, request: Request, api_key: str = Header(None, alias="X-API-Key")):
        self.start_time = time.time()
        
        # Verify the API key
        key_data = await verify_api_key(api_key)
        
        # Attach key data to request state for use in endpoints
        request.state.api_key_data = key_data
        
        return key_data

async def log_request_completion(
    request: Request,
    status_code: int,
    start_time: float,
    error_message: Optional[str] = None
):
    """Helper to log request after completion"""
    if hasattr(request.state, "api_key_data"):
        response_time_ms = int((time.time() - start_time) * 1000)
        
        await log_api_request(
            api_key_id=request.state.api_key_data["api_key_id"],
            endpoint=str(request.url.path),
            method=request.method,
            status_code=status_code,
            response_time_ms=response_time_ms,
            request=request,
            error_message=error_message
        )
