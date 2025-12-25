"""
OAuth Client Management Router for CleanEnroll
Handles CRUD operations for OAuth clients
"""
from fastapi import APIRouter, Depends, HTTPException, Header
from typing import List
from db.database import async_session_maker
from sqlalchemy import text

from models.oauth import (
    CreateOAuthClientRequest, UpdateOAuthClientRequest,
    OAuthClientResponse, OAuthClientCreatedResponse
)
from services.oauth_service import oauth_service

router = APIRouter(prefix="/api/developer/oauth", tags=["OAuth Clients"])


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


@router.post("/clients", response_model=OAuthClientCreatedResponse)
async def create_oauth_client(
    request: CreateOAuthClientRequest,
    authorization: str = Header(...)
):
    """Create a new OAuth client application"""
    uid = _get_uid_from_token(authorization)
    
    client_id, client_secret, secret_hash = oauth_service.generate_client_credentials()
    webhook_secret = oauth_service.generate_webhook_secret()
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""INSERT INTO oauth_clients
                   (client_id, client_secret_hash, name, description, user_id,
                    redirect_uris, allowed_scopes, webhook_secret, website_url,
                    privacy_policy_url, terms_of_service_url, logo_url)
                   VALUES (:client_id, :secret_hash, :name, :description, :user_id,
                           :redirect_uris, :allowed_scopes, :webhook_secret, :website_url,
                           :privacy_policy_url, :terms_of_service_url, :logo_url)
                   RETURNING id, created_at, updated_at, grant_types, is_active"""),
            {
                "client_id": client_id,
                "secret_hash": secret_hash,
                "name": request.name,
                "description": request.description,
                "user_id": uid,
                "redirect_uris": request.redirect_uris,
                "allowed_scopes": request.allowed_scopes,
                "webhook_secret": webhook_secret,
                "website_url": request.website_url,
                "privacy_policy_url": request.privacy_policy_url,
                "terms_of_service_url": request.terms_of_service_url,
                "logo_url": request.logo_url,
            }
        )
        row = result.fetchone()
        await session.commit()
        
        return {
            "id": str(row[0]),
            "client_id": client_id,
            "client_secret": client_secret,
            "name": request.name,
            "description": request.description,
            "redirect_uris": request.redirect_uris,
            "allowed_scopes": request.allowed_scopes,
            "grant_types": row[3],
            "is_active": row[4],
            "website_url": request.website_url,
            "logo_url": request.logo_url,
            "webhook_url": None,
            "created_at": row[1].isoformat(),
            "updated_at": row[2].isoformat(),
            "message": "Store the client_secret securely. It won't be shown again."
        }


@router.get("/clients", response_model=List[OAuthClientResponse])
async def list_oauth_clients(authorization: str = Header(...)):
    """List all OAuth clients for the authenticated user"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""SELECT id, client_id, name, description, redirect_uris,
                          allowed_scopes, grant_types, is_active, website_url,
                          logo_url, webhook_url, created_at, updated_at
                   FROM oauth_clients WHERE user_id = :uid
                   ORDER BY created_at DESC"""),
            {"uid": uid}
        )
        rows = result.fetchall()
        
        return [
            {
                "id": str(r[0]),
                "client_id": r[1],
                "name": r[2],
                "description": r[3],
                "redirect_uris": r[4],
                "allowed_scopes": r[5],
                "grant_types": r[6],
                "is_active": r[7],
                "website_url": r[8],
                "logo_url": r[9],
                "webhook_url": r[10],
                "created_at": r[11].isoformat(),
                "updated_at": r[12].isoformat(),
            }
            for r in rows
        ]


@router.get("/clients/{client_id}", response_model=OAuthClientResponse)
async def get_oauth_client(client_id: str, authorization: str = Header(...)):
    """Get a specific OAuth client"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""SELECT id, client_id, name, description, redirect_uris,
                          allowed_scopes, grant_types, is_active, website_url,
                          logo_url, webhook_url, created_at, updated_at
                   FROM oauth_clients
                   WHERE client_id = :client_id AND user_id = :uid"""),
            {"client_id": client_id, "uid": uid}
        )
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="OAuth client not found")
        
        return {
            "id": str(row[0]),
            "client_id": row[1],
            "name": row[2],
            "description": row[3],
            "redirect_uris": row[4],
            "allowed_scopes": row[5],
            "grant_types": row[6],
            "is_active": row[7],
            "website_url": row[8],
            "logo_url": row[9],
            "webhook_url": row[10],
            "created_at": row[11].isoformat(),
            "updated_at": row[12].isoformat(),
        }


@router.patch("/clients/{client_id}", response_model=OAuthClientResponse)
async def update_oauth_client(
    client_id: str,
    request: UpdateOAuthClientRequest,
    authorization: str = Header(...)
):
    """Update an OAuth client"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        # Verify ownership
        result = await session.execute(
            text("SELECT id FROM oauth_clients WHERE client_id = :client_id AND user_id = :uid"),
            {"client_id": client_id, "uid": uid}
        )
        if not result.fetchone():
            raise HTTPException(status_code=404, detail="OAuth client not found")
        
        # Build update query
        updates = ["updated_at = NOW()"]
        params = {"client_id": client_id, "uid": uid}
        
        if request.name is not None:
            updates.append("name = :name")
            params["name"] = request.name
        if request.description is not None:
            updates.append("description = :description")
            params["description"] = request.description
        if request.redirect_uris is not None:
            updates.append("redirect_uris = :redirect_uris")
            params["redirect_uris"] = request.redirect_uris
        if request.allowed_scopes is not None:
            updates.append("allowed_scopes = :allowed_scopes")
            params["allowed_scopes"] = request.allowed_scopes
        if request.website_url is not None:
            updates.append("website_url = :website_url")
            params["website_url"] = request.website_url
        if request.logo_url is not None:
            updates.append("logo_url = :logo_url")
            params["logo_url"] = request.logo_url
        if request.is_active is not None:
            updates.append("is_active = :is_active")
            params["is_active"] = request.is_active
        if request.webhook_url is not None:
            updates.append("webhook_url = :webhook_url")
            params["webhook_url"] = request.webhook_url
        
        result = await session.execute(
            text(f"""UPDATE oauth_clients SET {', '.join(updates)}
                   WHERE client_id = :client_id AND user_id = :uid
                   RETURNING id, client_id, name, description, redirect_uris,
                             allowed_scopes, grant_types, is_active, website_url,
                             logo_url, webhook_url, created_at, updated_at"""),
            params
        )
        row = result.fetchone()
        await session.commit()
        
        return {
            "id": str(row[0]),
            "client_id": row[1],
            "name": row[2],
            "description": row[3],
            "redirect_uris": row[4],
            "allowed_scopes": row[5],
            "grant_types": row[6],
            "is_active": row[7],
            "website_url": row[8],
            "logo_url": row[9],
            "webhook_url": row[10],
            "created_at": row[11].isoformat(),
            "updated_at": row[12].isoformat(),
        }


@router.delete("/clients/{client_id}")
async def delete_oauth_client(client_id: str, authorization: str = Header(...)):
    """Delete an OAuth client"""
    uid = _get_uid_from_token(authorization)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("DELETE FROM oauth_clients WHERE client_id = :client_id AND user_id = :uid"),
            {"client_id": client_id, "uid": uid}
        )
        await session.commit()
        
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="OAuth client not found")
        
        return {"message": "OAuth client deleted successfully"}


@router.post("/clients/{client_id}/rotate-secret")
async def rotate_client_secret(client_id: str, authorization: str = Header(...)):
    """Rotate the client secret for an OAuth client"""
    uid = _get_uid_from_token(authorization)
    
    _, new_secret, new_hash = oauth_service.generate_client_credentials()
    # Keep the same client_id prefix
    new_secret = f"ces_{new_secret.split('_', 1)[1]}"
    new_hash = oauth_service.hash_token(new_secret)
    
    async with async_session_maker() as session:
        result = await session.execute(
            text("""UPDATE oauth_clients
                   SET client_secret_hash = :new_hash, updated_at = NOW()
                   WHERE client_id = :client_id AND user_id = :uid
                   RETURNING id"""),
            {"new_hash": new_hash, "client_id": client_id, "uid": uid}
        )
        row = result.fetchone()
        await session.commit()
        
        if not row:
            raise HTTPException(status_code=404, detail="OAuth client not found")
        
        return {
            "client_id": client_id,
            "client_secret": new_secret,
            "message": "Store the new client_secret securely. It won't be shown again."
        }
