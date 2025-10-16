"""
Base Pydantic models for data validation and sanitization
"""
from datetime import datetime
from typing import Optional, Dict, List, Any, Union
from pydantic import BaseModel, Field, EmailStr, field_validator, AnyHttpUrl
try:
    # Pydantic v2
    from pydantic import ConfigDict  # type: ignore
except Exception:
    ConfigDict = dict  # type: ignore
import re
import bleach


class BaseDBModel(BaseModel):
    """Base model with common validation and sanitization methods"""
    
    @field_validator('*', mode='before')
    def sanitize_strings(cls, v, info):
        """Sanitize string inputs to prevent XSS attacks"""
        if isinstance(v, str) and info.field_name:
            # Use bleach to sanitize HTML content
            return bleach.clean(v.strip(), strip=True)
        return v


class UserModel(BaseDBModel):
    """User model for validation and sanitization"""
    uid: str
    email: EmailStr
    display_name: Optional[str] = None
    photo_url: Optional[str] = None
    plan: str = 'free'
    forms_count: int = 0
    signup_ip: Optional[str] = None
    signup_country: Optional[str] = None
    signup_geo_lat: Optional[float] = None
    signup_geo_lon: Optional[float] = None
    signup_user_agent: Optional[str] = None
    signup_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    @field_validator('uid')
    def validate_uid(cls, v):
        """Validate Firebase UID format"""
        if not re.match(r'^[a-zA-Z0-9]{28}$', v):
            raise ValueError('Invalid Firebase UID format')
        return v
    
    @field_validator('display_name')
    def validate_display_name(cls, v):
        """Validate and sanitize display name"""
        if v is None:
            return v
        # Remove any HTML tags and limit length
        sanitized = bleach.clean(v.strip(), strip=True)
        if len(sanitized) > 255:
            sanitized = sanitized[:255]
        return sanitized


class FormModel(BaseDBModel):
    """Form model for validation and sanitization"""
    # Allow population by both snake_case and camelCase aliases
    try:
        model_config = ConfigDict(populate_by_name=True)
    except Exception:
        # Fallback for older Pydantic; harmless
        pass
    id: Optional[str] = None
    user_id: str
    title: str
    name: str
    description: Optional[str] = None
    form_type: str = 'simple'
    is_published: bool = False
    views: int = 0
    submissions: int = 0
    submission_limit: int = 0
    fields: Union[Dict[str, Any], List[Any]] = Field(default_factory=dict)
    theme: Dict[str, Any] = Field(default_factory=dict)
    branding: Dict[str, Any] = Field(default_factory=dict)
    allowed_domains: List[str] = Field(default_factory=list)
    # New controls synced from builder to Neon (DB columns expected)
    password_protection_enabled: bool = Field(default=False, alias="passwordProtectionEnabled")
    password_hash: Optional[str] = Field(default=None, alias="passwordHash")
    prevent_duplicate_by_ip: bool = Field(default=False, alias="preventDuplicateByIP")
    duplicate_window_hours: int = Field(default=24, alias="duplicateWindowHours")
    show_powered_by: bool = Field(default=True, alias="showPoweredBy")
    privacy_policy_url: Optional[AnyHttpUrl] = Field(default=None, alias="privacyPolicyUrl")
    idempotency_key: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    @field_validator('name')
    def validate_form_name(cls, v):
        """Validate form name (used in URLs)"""
        # Ensure name is URL-friendly
        if not re.match(r'^[a-z0-9-]+$', v):
            raise ValueError('Form name must contain only lowercase letters, numbers, and hyphens')
        return v
    
    @field_validator('allowed_domains')
    def validate_domains(cls, v):
        """Validate domain or IP format"""
        if isinstance(v, list):
            result = []
            for raw in v:
                item = (raw or "").strip().lower()
                if not item:
                    continue
                # Allow localhost and common localhost domain
                if item in ("localhost", "localhost.localdomain"):
                    result.append("localhost")
                    continue
                # Allow IPv4 addresses
                if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', item):
                    try:
                        parts = [int(p) for p in item.split('.')]
                        if all(0 <= p <= 255 for p in parts):
                            result.append(item)
                            continue
                        else:
                            raise ValueError
                    except Exception:
                        raise ValueError(f'Invalid IPv4 address: {raw}')
                # Standard domain pattern (labels 1-63 chars, letters/digits/hyphens, at least one dot)
                if not re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+', item):
                    raise ValueError(f'Invalid domain format: {raw}')
                result.append(item)
            return result
        return v


class SubmissionModel(BaseDBModel):
    """Submission model for validation and sanitization"""
    id: Optional[str] = None
    form_id: str
    form_owner_id: str
    data: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    country_code: Optional[str] = None
    user_agent: Optional[str] = None
    submitted_at: Optional[datetime] = None
    
    @field_validator('data')
    def sanitize_submission_data(cls, v):
        """Sanitize all string values in submission data"""
        if not isinstance(v, dict):
            return {}
            
        # Recursively sanitize all string values
        def sanitize_dict(d):
            result = {}
            for key, value in d.items():
                if isinstance(value, str):
                    result[key] = bleach.clean(value.strip(), strip=True)
                elif isinstance(value, dict):
                    result[key] = sanitize_dict(value)
                elif isinstance(value, list):
                    result[key] = [
                        sanitize_dict(item) if isinstance(item, dict) 
                        else bleach.clean(item, strip=True) if isinstance(item, str)
                        else item
                        for item in value
                    ]
                else:
                    result[key] = value
            return result
            
        return sanitize_dict(v)


class AnalyticsModel(BaseDBModel):
    """Analytics model for validation and sanitization"""
    id: Optional[str] = None
    form_id: str
    event_type: str
    data: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    country_code: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: Optional[datetime] = None