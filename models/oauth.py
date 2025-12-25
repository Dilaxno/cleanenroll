"""
OAuth 2.0 Pydantic Models for CleanEnroll
"""
from pydantic import BaseModel, Field, field_validator, HttpUrl
from typing import Optional, List
from datetime import datetime
from enum import Enum


class OAuthScope(str, Enum):
    """Available OAuth scopes"""
    FORMS_READ = "forms:read"
    FORMS_WRITE = "forms:write"
    SUBMISSIONS_READ = "submissions:read"
    SUBMISSIONS_WRITE = "submissions:write"
    ANALYTICS_READ = "analytics:read"
    PAYMENTS_READ = "payments:read"
    WEBHOOKS_MANAGE = "webhooks:manage"
    PROFILE_READ = "profile:read"


SCOPE_DESCRIPTIONS = {
    OAuthScope.FORMS_READ: "View your forms and form configurations",
    OAuthScope.FORMS_WRITE: "Create, update, and delete your forms",
    OAuthScope.SUBMISSIONS_READ: "View form submissions",
    OAuthScope.SUBMISSIONS_WRITE: "Create and manage form submissions",
    OAuthScope.ANALYTICS_READ: "View form analytics and statistics",
    OAuthScope.PAYMENTS_READ: "View payment information",
    OAuthScope.WEBHOOKS_MANAGE: "Manage webhook configurations",
    OAuthScope.PROFILE_READ: "View your basic profile information",
}


class GrantType(str, Enum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"


# Client Management Models
class CreateOAuthClientRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    redirect_uris: List[str] = Field(..., min_length=1)
    allowed_scopes: List[str] = Field(default=["forms:read"])
    website_url: Optional[str] = None
    privacy_policy_url: Optional[str] = None
    terms_of_service_url: Optional[str] = None
    logo_url: Optional[str] = None

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, v):
        for uri in v:
            if not uri.startswith(("https://", "http://localhost", "http://127.0.0.1")):
                raise ValueError(f"Redirect URI must use HTTPS (except localhost): {uri}")
        return v

    @field_validator("allowed_scopes")
    @classmethod
    def validate_scopes(cls, v):
        valid_scopes = {s.value for s in OAuthScope}
        for scope in v:
            if scope not in valid_scopes:
                raise ValueError(f"Invalid scope: {scope}")
        return v


class UpdateOAuthClientRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    redirect_uris: Optional[List[str]] = None
    allowed_scopes: Optional[List[str]] = None
    website_url: Optional[str] = None
    privacy_policy_url: Optional[str] = None
    terms_of_service_url: Optional[str] = None
    logo_url: Optional[str] = None
    is_active: Optional[bool] = None
    webhook_url: Optional[str] = None


class OAuthClientResponse(BaseModel):
    id: str
    client_id: str
    name: str
    description: Optional[str]
    redirect_uris: List[str]
    allowed_scopes: List[str]
    grant_types: List[str]
    is_active: bool
    website_url: Optional[str]
    logo_url: Optional[str]
    webhook_url: Optional[str]
    created_at: str
    updated_at: str


class OAuthClientCreatedResponse(OAuthClientResponse):
    client_secret: str
    message: str = "Store the client_secret securely. It won't be shown again."


# Authorization Models
class AuthorizeRequest(BaseModel):
    response_type: str = Field(..., pattern="^code$")
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = Field(None, pattern="^(plain|S256)$")


class ConsentRequest(BaseModel):
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    approved: bool


class ConsentScreenData(BaseModel):
    client_name: str
    client_logo: Optional[str]
    client_website: Optional[str]
    requested_scopes: List[dict]
    redirect_uri: str
    state: str


# Token Models
class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    client_id: str
    client_secret: Optional[str] = None
    refresh_token: Optional[str] = None
    code_verifier: Optional[str] = None

    @field_validator("grant_type")
    @classmethod
    def validate_grant_type(cls, v):
        if v not in ["authorization_code", "refresh_token"]:
            raise ValueError("Invalid grant_type")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: str


class TokenIntrospectionResponse(BaseModel):
    active: bool
    scope: Optional[str] = None
    client_id: Optional[str] = None
    user_id: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None


class RevokeTokenRequest(BaseModel):
    token: str
    token_type_hint: Optional[str] = Field(None, pattern="^(access_token|refresh_token)$")


# Webhook Models
class WebhookEventType(str, Enum):
    SUBMISSION_CREATED = "submission.created"
    PAYMENT_SUCCEEDED = "payment.succeeded"
    FORM_UPDATED = "form.updated"
    FORM_PUBLISHED = "form.published"
    FORM_DELETED = "form.deleted"


class RegisterWebhookRequest(BaseModel):
    url: str
    events: List[str]

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        if not v.startswith("https://"):
            raise ValueError("Webhook URL must use HTTPS")
        return v

    @field_validator("events")
    @classmethod
    def validate_events(cls, v):
        valid_events = {e.value for e in WebhookEventType}
        for event in v:
            if event not in valid_events:
                raise ValueError(f"Invalid event type: {event}")
        return v


class WebhookPayload(BaseModel):
    id: str
    event: str
    created_at: str
    data: dict


class WebhookResponse(BaseModel):
    id: str
    client_id: str
    webhook_url: str
    events: List[str]
    is_active: bool
    created_at: str


# Error Models
class OAuthError(BaseModel):
    error: str
    error_description: Optional[str] = None
    error_uri: Optional[str] = None
