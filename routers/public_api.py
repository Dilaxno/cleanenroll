"""
Public API Endpoints for Developer Integration
These endpoints are used by developers to integrate CleanEnroll validation and protection
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from routers.api_middleware import APIKeyDependency, log_api_request, log_request_completion
from db.database import async_session_maker, get_connection as get_db_connection
from sqlalchemy import text
import re
import time

router = APIRouter(prefix="/api/v1", tags=["Public API"])
api_key_auth = APIKeyDependency()

# Pydantic Models
class ValidateEmailRequest(BaseModel):
    email: EmailStr
    check_disposable: bool = True
    check_mx: bool = True

class ValidateEmailResponse(BaseModel):
    valid: bool
    email: str
    is_disposable: bool
    has_mx_record: bool
    suggestion: Optional[str] = None
    reason: Optional[str] = None

class ValidateFormDataRequest(BaseModel):
    fields: Dict[str, Any]
    rules: Optional[Dict[str, Any]] = None

class ValidateFormDataResponse(BaseModel):
    valid: bool
    errors: Dict[str, List[str]]
    warnings: Dict[str, List[str]]

class CheckIPRequest(BaseModel):
    ip_address: str
    country_restrictions: Optional[List[str]] = None  # ISO country codes

class CheckIPResponse(BaseModel):
    allowed: bool
    ip_address: str
    country_code: Optional[str]
    country_name: Optional[str]
    reason: Optional[str]

class ProtectionCheckRequest(BaseModel):
    ip_address: str
    user_agent: Optional[str] = None
    check_bot: bool = True
    check_vpn: bool = False

class ProtectionCheckResponse(BaseModel):
    safe: bool
    ip_address: str
    is_bot: bool
    is_vpn: bool
    risk_score: int  # 0-100
    reasons: List[str]

class RateLimitCheckRequest(BaseModel):
    identifier: str  # IP, email, or custom ID
    limit: int = 10
    window_seconds: int = 60

class RateLimitCheckResponse(BaseModel):
    allowed: bool
    identifier: str
    current_count: int
    limit: int
    reset_in_seconds: int

# Helper Functions
async def check_disposable_email(email: str) -> bool:
    """Check if email is from a disposable domain"""
    disposable_domains = {
        'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
        'throwaway.email', 'temp-mail.org', 'fakeinbox.com', 'maildrop.cc',
        'yopmail.com', 'trashmail.com', 'getnada.com', 'sharklasers.com'
    }
    
    domain = email.split('@')[1].lower()
    return domain in disposable_domains

def suggest_email_correction(email: str) -> Optional[str]:
    """Suggest common email typo corrections"""
    common_domains = {
        'gmail': 'gmail.com',
        'yahoo': 'yahoo.com',
        'hotmail': 'hotmail.com',
        'outlook': 'outlook.com'
    }
    
    # Common typos
    typo_map = {
        'gmial.com': 'gmail.com',
        'gmai.com': 'gmail.com',
        'yahooo.com': 'yahoo.com',
        'yaho.com': 'yahoo.com',
        'hotmial.com': 'hotmail.com',
        'outlok.com': 'outlook.com'
    }
    
    parts = email.split('@')
    if len(parts) != 2:
        return None
    
    username, domain = parts
    domain = domain.lower()
    
    if domain in typo_map:
        return f"{username}@{typo_map[domain]}"
    
    return None

def validate_field_value(field_name: str, value: Any, rules: Dict) -> List[str]:
    """Validate a single field value against rules"""
    errors = []
    
    if not value and rules.get('required', False):
        errors.append(f"{field_name} is required")
        return errors
    
    if not value:
        return errors
    
    # String validations
    if isinstance(value, str):
        if 'min_length' in rules and len(value) < rules['min_length']:
            errors.append(f"{field_name} must be at least {rules['min_length']} characters")
        
        if 'max_length' in rules and len(value) > rules['max_length']:
            errors.append(f"{field_name} must be at most {rules['max_length']} characters")
        
        if 'pattern' in rules:
            if not re.match(rules['pattern'], value):
                errors.append(f"{field_name} format is invalid")
    
    # Number validations
    if isinstance(value, (int, float)):
        if 'min' in rules and value < rules['min']:
            errors.append(f"{field_name} must be at least {rules['min']}")
        
        if 'max' in rules and value > rules['max']:
            errors.append(f"{field_name} must be at most {rules['max']}")
    
    return errors

def calculate_risk_score(user_agent: str, ip_data: dict) -> int:
    """Calculate risk score based on various factors"""
    score = 0
    
    # Check user agent
    if not user_agent or len(user_agent) < 20:
        score += 30
    
    bot_indicators = ['bot', 'crawler', 'spider', 'scraper', 'headless']
    if user_agent and any(indicator in user_agent.lower() for indicator in bot_indicators):
        score += 40
    
    # Check IP characteristics
    if ip_data.get('is_vpn'):
        score += 25
    
    if ip_data.get('is_proxy'):
        score += 20
    
    return min(100, score)

# API Endpoints

@router.post("/validate/email", response_model=ValidateEmailResponse)
async def validate_email(
    request: Request,
    data: ValidateEmailRequest,
    key_data: dict = Depends(api_key_auth)
):
    """
    Validate email address with disposable check and suggestions
    
    **Permissions Required:** validate
    """
    start_time = time.time()
    
    try:
        # Check permissions
        if not key_data['permissions'].get('validate', False):
            raise HTTPException(
                status_code=403,
                detail="API key does not have 'validate' permission"
            )
        
        is_disposable = False
        if data.check_disposable:
            is_disposable = await check_disposable_email(data.email)
        
        # Email format is already validated by EmailStr
        valid = not is_disposable
        suggestion = suggest_email_correction(data.email)
        
        reason = None
        if is_disposable:
            reason = "Disposable email domain detected"
        elif suggestion:
            reason = "Possible typo detected"
        
        response = {
            "valid": valid,
            "email": data.email,
            "is_disposable": is_disposable,
            "has_mx_record": True,  # Would need actual DNS lookup
            "suggestion": suggestion,
            "reason": reason
        }
        
        await log_request_completion(request, 200, start_time)
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        await log_request_completion(request, 500, start_time, str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/validate/form", response_model=ValidateFormDataResponse)
async def validate_form_data(
    request: Request,
    data: ValidateFormDataRequest,
    key_data: dict = Depends(api_key_auth)
):
    """
    Validate form data against custom rules
    
    **Permissions Required:** validate
    """
    start_time = time.time()
    
    try:
        if not key_data['permissions'].get('validate', False):
            raise HTTPException(
                status_code=403,
                detail="API key does not have 'validate' permission"
            )
        
        errors = {}
        warnings = {}
        
        if data.rules:
            for field_name, field_rules in data.rules.items():
                field_value = data.fields.get(field_name)
                field_errors = validate_field_value(field_name, field_value, field_rules)
                
                if field_errors:
                    errors[field_name] = field_errors
        
        response = {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }
        
        await log_request_completion(request, 200, start_time)
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        await log_request_completion(request, 500, start_time, str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/protect/check-ip", response_model=CheckIPResponse)
async def check_ip_address(
    request: Request,
    data: CheckIPRequest,
    key_data: dict = Depends(api_key_auth)
):
    """
    Check if IP address is allowed based on geo-restrictions
    
    **Permissions Required:** protect
    """
    start_time = time.time()
    
    try:
        if not key_data['permissions'].get('protect', False):
            raise HTTPException(
                status_code=403,
                detail="API key does not have 'protect' permission"
            )
        
        # In production, use GeoIP lookup
        # For now, return mock data
        country_code = "US"
        country_name = "United States"
        
        allowed = True
        reason = None
        
        if data.country_restrictions:
            if country_code not in data.country_restrictions:
                allowed = False
                reason = f"IP from {country_name} is not in allowed countries"
        
        response = {
            "allowed": allowed,
            "ip_address": data.ip_address,
            "country_code": country_code,
            "country_name": country_name,
            "reason": reason
        }
        
        await log_request_completion(request, 200, start_time)
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        await log_request_completion(request, 500, start_time, str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/protect/check", response_model=ProtectionCheckResponse)
async def protection_check(
    request: Request,
    data: ProtectionCheckRequest,
    key_data: dict = Depends(api_key_auth)
):
    """
    Comprehensive protection check (bot detection, VPN detection, risk scoring)
    
    **Permissions Required:** protect
    """
    start_time = time.time()
    
    try:
        if not key_data['permissions'].get('protect', False):
            raise HTTPException(
                status_code=403,
                detail="API key does not have 'protect' permission"
            )
        
        is_bot = False
        is_vpn = False
        reasons = []
        
        if data.check_bot and data.user_agent:
            bot_indicators = ['bot', 'crawler', 'spider', 'scraper', 'headless']
            if any(indicator in data.user_agent.lower() for indicator in bot_indicators):
                is_bot = True
                reasons.append("Bot detected in user agent")
        
        if data.check_vpn:
            # In production, use VPN detection service
            # For now, mock
            pass
        
        ip_data = {"is_vpn": is_vpn, "is_proxy": False}
        risk_score = calculate_risk_score(data.user_agent or "", ip_data)
        
        safe = risk_score < 50 and not is_bot
        
        response = {
            "safe": safe,
            "ip_address": data.ip_address,
            "is_bot": is_bot,
            "is_vpn": is_vpn,
            "risk_score": risk_score,
            "reasons": reasons
        }
        
        await log_request_completion(request, 200, start_time)
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        await log_request_completion(request, 500, start_time, str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/rate-limit/check", response_model=RateLimitCheckResponse)
async def check_rate_limit(
    request: Request,
    data: RateLimitCheckRequest,
    key_data: dict = Depends(api_key_auth)
):
    """
    Check rate limit for an identifier (IP, email, etc.)
    
    **Permissions Required:** protect
    """
    start_time = time.time()
    
    try:
        if not key_data['permissions'].get('protect', False):
            raise HTTPException(
                status_code=403,
                detail="API key does not have 'protect' permission"
            )
        
        conn = await get_db_connection()
        try:
            # Check rate limit in database
            # This would use a rate limiting table in production
            # For now, return mock data
            
            current_count = 5  # Mock
            allowed = current_count < data.limit
            reset_in_seconds = data.window_seconds
            
            response = {
                "allowed": allowed,
                "identifier": data.identifier,
                "current_count": current_count,
                "limit": data.limit,
                "reset_in_seconds": reset_in_seconds
            }
            
            await log_request_completion(request, 200, start_time)
            return response
            
        finally:
            await conn.close()
        
    except HTTPException:
        raise
    except Exception as e:
        await log_request_completion(request, 500, start_time, str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    """Health check endpoint (no authentication required)"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": time.time()
    }
