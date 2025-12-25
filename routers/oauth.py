"""
OAuth 2.0 Provider Router for CleanEnroll
Implements RFC 6749 compliant OAuth 2.0 authorization server endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Header, Request, Query, Form
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs
import logging

from models.oauth import (
    AuthorizeRequest, ConsentRequest, TokenRequest, TokenResponse,
    RevokeTokenRequest, OAuthError, SCOPE_DESCRIPTIONS, OAuthScope
)
from services.oauth_service import oauth_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/oauth", tags=["OAuth 2.0"])


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


def _build_error_redirect(redirect_uri: str, error: str, description: str, state: str = None) -> str:
    """Build OAuth error redirect URL"""
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return f"{redirect_uri}{separator}{urlencode(params)}"


# Authorization Endpoint
@router.get("/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(...),
    state: str = Query(...),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: Optional[str] = Query(None),
    authorization: str = Header(None)
):
    """
    OAuth 2.0 Authorization Endpoint
    Initiates the authorization code flow
    """
    # Validate response_type
    if response_type != "code":
        raise HTTPException(
            status_code=400,
            detail={"error": "unsupported_response_type", "error_description": "Only 'code' response type is supported"}
        )

    # Validate client
    client = await oauth_service.get_client(client_id)
    if not client:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_client", "error_description": "Unknown client_id"}
        )

    if not client["is_active"]:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_client", "error_description": "Client is inactive"}
        )

    # Validate redirect_uri
    if not await oauth_service.validate_redirect_uri(client_id, redirect_uri):
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_redirect_uri", "error_description": "Redirect URI not registered"}
        )

    # Validate scopes
    valid, valid_scopes = await oauth_service.validate_scopes(client_id, scope)
    if not valid:
        return RedirectResponse(
            url=_build_error_redirect(redirect_uri, "invalid_scope", "Requested scope not allowed", state),
            status_code=302
        )

    # Validate PKCE if provided
    if code_challenge and code_challenge_method not in [None, "plain", "S256"]:
        return RedirectResponse(
            url=_build_error_redirect(redirect_uri, "invalid_request", "Invalid code_challenge_method", state),
            status_code=302
        )

    # Check if user is authenticated
    if not authorization:
        # Return consent screen data for frontend to render
        return JSONResponse(
            status_code=401,
            content={
                "error": "login_required",
                "error_description": "User authentication required",
                "consent_data": {
                    "client_id": client_id,
                    "client_name": client["name"],
                    "client_logo": client["logo_url"],
                    "client_website": client["website_url"],
                    "redirect_uri": redirect_uri,
                    "scope": scope,
                    "state": state,
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                    "requested_scopes": [
                        {"scope": s, "description": SCOPE_DESCRIPTIONS.get(OAuthScope(s), s)}
                        for s in scope.split() if s in [e.value for e in OAuthScope]
                    ]
                }
            }
        )

    # Verify user token
    try:
        user_id = _get_uid_from_token(authorization)
    except HTTPException:
        return RedirectResponse(
            url=_build_error_redirect(redirect_uri, "access_denied", "Invalid user authentication", state),
            status_code=302
        )

    # Check existing consent
    has_consent = await oauth_service.check_user_consent(user_id, client_id, scope)
    
    if has_consent:
        # User already consented, generate code directly
        code = await oauth_service.create_authorization_code(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method
        )
        separator = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(
            url=f"{redirect_uri}{separator}code={code}&state={state}",
            status_code=302
        )

    # Return consent screen data
    return JSONResponse(content={
        "consent_required": True,
        "client_id": client_id,
        "client_name": client["name"],
        "client_logo": client["logo_url"],
        "client_website": client["website_url"],
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "requested_scopes": [
            {"scope": s, "description": SCOPE_DESCRIPTIONS.get(OAuthScope(s), s)}
            for s in scope.split() if s in [e.value for e in OAuthScope]
        ]
    })


@router.post("/authorize/consent")
async def authorize_consent(
    request: ConsentRequest,
    authorization: str = Header(...)
):
    """
    Handle user consent decision
    """
    user_id = _get_uid_from_token(authorization)

    # Validate client and redirect_uri again
    client = await oauth_service.get_client(request.client_id)
    if not client or not client["is_active"]:
        raise HTTPException(status_code=400, detail="Invalid client")

    if not await oauth_service.validate_redirect_uri(request.client_id, request.redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    if not request.approved:
        # User denied consent
        return JSONResponse(content={
            "redirect_url": _build_error_redirect(
                request.redirect_uri, "access_denied", "User denied consent", request.state
            )
        })

    # Save consent
    await oauth_service.save_user_consent(user_id, request.client_id, request.scope)

    # Generate authorization code
    code = await oauth_service.create_authorization_code(
        client_id=request.client_id,
        user_id=user_id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        code_challenge=request.code_challenge,
        code_challenge_method=request.code_challenge_method
    )

    separator = "&" if "?" in request.redirect_uri else "?"
    redirect_url = f"{request.redirect_uri}{separator}code={code}&state={request.state}"

    return JSONResponse(content={"redirect_url": redirect_url})


# Token Endpoint
@router.post("/token", response_model=TokenResponse)
async def token(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None)
):
    """
    OAuth 2.0 Token Endpoint
    Exchange authorization code or refresh token for access token
    """
    # Validate client credentials
    client = await oauth_service.get_client(client_id)
    if not client:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "Unknown client"}
        )

    if not client["is_active"]:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "Client is inactive"}
        )

    # Confidential clients must provide client_secret
    if client["is_confidential"]:
        if not client_secret:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_client", "error_description": "Client secret required"}
            )
        if not await oauth_service.verify_client_secret(client_id, client_secret):
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_client", "error_description": "Invalid client credentials"}
            )

    # Handle grant types
    if grant_type == "authorization_code":
        if not code or not redirect_uri:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_request", "error_description": "Missing code or redirect_uri"}
            )

        result = await oauth_service.exchange_authorization_code(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier
        )

        if not result:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}
            )

        return result

    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_request", "error_description": "Missing refresh_token"}
            )

        result = await oauth_service.refresh_access_token(
            refresh_token=refresh_token,
            client_id=client_id
        )

        if not result:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_grant", "error_description": "Invalid or expired refresh token"}
            )

        return result

    else:
        raise HTTPException(
            status_code=400,
            detail={"error": "unsupported_grant_type", "error_description": f"Grant type '{grant_type}' not supported"}
        )


# Token Revocation Endpoint
@router.post("/revoke")
async def revoke_token(
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: Optional[str] = Form(None)
):
    """
    OAuth 2.0 Token Revocation Endpoint (RFC 7009)
    """
    # Validate client
    client = await oauth_service.get_client(client_id)
    if not client:
        raise HTTPException(status_code=401, detail="Invalid client")

    if client["is_confidential"] and client_secret:
        if not await oauth_service.verify_client_secret(client_id, client_secret):
            raise HTTPException(status_code=401, detail="Invalid client credentials")

    # Revoke token (always returns 200 per RFC 7009)
    await oauth_service.revoke_token(token, token_type_hint)
    
    return JSONResponse(content={}, status_code=200)


# Token Introspection Endpoint
@router.post("/introspect")
async def introspect_token(
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...)
):
    """
    OAuth 2.0 Token Introspection Endpoint (RFC 7662)
    """
    # Validate client credentials
    if not await oauth_service.verify_client_secret(client_id, client_secret):
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    token_data = await oauth_service.validate_access_token(token)
    
    if not token_data:
        return JSONResponse(content={"active": False})

    return JSONResponse(content={
        "active": True,
        "scope": token_data["scope"],
        "client_id": token_data["client_id"],
        "user_id": token_data["user_id"],
        "exp": int(token_data["expires_at"].timestamp()),
    })
