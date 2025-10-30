"""
API Key Authentication Middleware
Validates API keys and tracks usage
"""
from fastapi import HTTPException, Header, Request
from typing import Optional
import hashlib
from datetime import datetime
from db.database import async_session_maker
from sqlalchemy import text
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
    
    async with async_session_maker() as session:
        # Verify API key
        result = await session.execute(
            text("""SELECT k.*, q.monthly_requests, q.requests_used
               FROM api_keys k
               LEFT JOIN api_quotas q ON k.user_id = q.user_id
               WHERE k.key_hash = :key_hash AND k.is_active = true"""),
            {"key_hash": key_hash}
        )
        row = result.fetchone()
        
        if not row:
            raise HTTPException(
                status_code=401,
                detail="Invalid or inactive API key"
            )
        
        # Check expiration (index 7 is expires_at)
        if row[7] and row[7] < datetime.utcnow():
            raise HTTPException(
                status_code=401,
                detail="API key has expired"
            )
        
        # Check quota (last two columns from join)
        monthly_requests = row[-2]
        requests_used = row[-1]
        if monthly_requests and requests_used >= monthly_requests:
            # Get reset date for error message
            quota_result = await session.execute(
                text("SELECT reset_date FROM api_quotas WHERE user_id = :user_id"),
                {"user_id": row[1]}  # user_id is index 1
            )
            quota_row = quota_result.fetchone()
            reset_date = quota_row[0].isoformat() if quota_row else "unknown"
            raise HTTPException(
                status_code=429,
                detail=f"API quota exceeded. Limit: {monthly_requests}/month. Resets: {reset_date}"
            )
        
        # Update last used timestamp
        await session.execute(
            text("UPDATE api_keys SET last_used_at = NOW() WHERE id = :key_id"),
            {"key_id": row[0]}  # id is index 0
        )
        await session.commit()
        
        return {
            "api_key_id": row[0],  # id
            "user_id": row[1],  # user_id
            "environment": row[4],  # environment
            "permissions": row[5],  # permissions
            "quota_used": requests_used + 1,
            "quota_limit": monthly_requests
        }

async def log_api_request(
    api_key_data: dict,
    endpoint: str,
    method: str,
    status_code: int,
    response_time_ms: int,
    request: Request,
    error_message: Optional[str] = None
):
    """Log API request for analytics"""
    async with async_session_maker() as session:
        # Increment quota usage
        await session.execute(
            text("""UPDATE api_quotas 
               SET requests_used = requests_used + 1,
                   updated_at = NOW()
               WHERE user_id = :user_id"""),
            {"user_id": api_key_data['user_id']}
        )
        
        # Log the request
        await session.execute(
            text("""INSERT INTO api_usage_logs 
               (api_key_id, endpoint, method, status_code, response_time_ms, ip_address, error_message)
               VALUES (:api_key_id, :endpoint, :method, :status_code, :response_time_ms, :ip_address, :error_message)"""),
            {
                "api_key_id": api_key_data['api_key_id'],
                "endpoint": endpoint,
                "method": method,
                "status_code": status_code,
                "response_time_ms": response_time_ms,
                "ip_address": request.client.host if request.client else None,
                "error_message": error_message
            }
        )
        await session.commit()

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
