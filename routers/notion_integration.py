"""
Notion Integration Router
Handles Notion OAuth, database selection, field mapping, and form submission sync
"""

from fastapi import APIRouter, Depends, HTTPException, status, Header, Request, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import firebase_admin.auth
from db.database import async_session_maker
from sqlalchemy import text
import logging
import os
import httpx
import json

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notion", tags=["notion-integration"])

# Notion API configuration
NOTION_API_VERSION = "2022-06-28"
NOTION_AUTH_URL = "https://api.notion.com/v1/oauth/authorize"
NOTION_TOKEN_URL = "https://api.notion.com/v1/oauth/token"
NOTION_API_BASE = "https://api.notion.com/v1"

# OAuth credentials from environment
NOTION_CLIENT_ID = os.getenv("NOTION_CLIENT_ID", "")
NOTION_CLIENT_SECRET = os.getenv("NOTION_CLIENT_SECRET", "")
NOTION_REDIRECT_URI = os.getenv("NOTION_REDIRECT_URI", "http://localhost:3000/integrations/notion/callback")
ALLOWED_OAUTH_REDIRECT_HOSTS = os.getenv("ALLOWED_OAUTH_REDIRECT_HOSTS", "cleanenroll.com,localhost,127.0.0.1").split(",")


# ============================================================================
# Request/Response Models
# ============================================================================

class NotionOAuthCallback(BaseModel):
    code: str
    form_id: int


class NotionDatabaseSelect(BaseModel):
    form_id: int
    database_id: str
    database_name: str
    field_mappings: Dict[str, str] = {}


class NotionIntegrationResponse(BaseModel):
    form_id: int
    database_id: str
    database_name: Optional[str]
    field_mappings: Dict[str, str]
    enabled: bool
    workspace_name: Optional[str]


class NotionDatabase(BaseModel):
    id: str
    title: str
    properties: Dict[str, Any]


# ============================================================================
# Authentication Helper
# ============================================================================

async def get_current_user_uid(authorization: str = Header(None)) -> str:
    """Extract and verify Firebase token from Authorization header"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header"
        )
    
    token = authorization.split("Bearer ")[1]
    try:
        decoded_token = firebase_admin.auth.verify_id_token(token)
        return decoded_token["uid"]
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )


# ============================================================================
# Notion API Helpers
# ============================================================================

async def get_notion_databases(access_token: str) -> List[Dict[str, Any]]:
    """Fetch all databases accessible to the integration"""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Notion-Version": NOTION_API_VERSION,
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        # Search for databases
        response = await client.post(
            f"{NOTION_API_BASE}/search",
            headers=headers,
            json={
                "filter": {
                    "property": "object",
                    "value": "database"
                }
            }
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch Notion databases: {response.text}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to fetch Notion databases"
            )
        
        data = response.json()
        databases = []
        
        for db in data.get("results", []):
            title = ""
            if db.get("title"):
                title = "".join([t.get("plain_text", "") for t in db["title"]])
            
            databases.append({
                "id": db["id"],
                "title": title or "Untitled",
                "properties": db.get("properties", {})
            })
        
        return databases


async def create_notion_page(access_token: str, database_id: str, properties: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new page in a Notion database"""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Notion-Version": NOTION_API_VERSION,
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{NOTION_API_BASE}/pages",
            headers=headers,
            json={
                "parent": {"database_id": database_id},
                "properties": properties
            }
        )
        
        if response.status_code not in [200, 201]:
            logger.error(f"Failed to create Notion page: {response.text}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create Notion page: {response.text}"
            )
        
        return response.json()


# ============================================================================
# Public Endpoints
# ============================================================================

@router.get("/oauth/authorize")
async def get_notion_auth_url(uid: str = Depends(get_current_user_uid)):
    """Get Notion OAuth authorization URL"""
    if not NOTION_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Notion integration not configured"
        )
    
    auth_url = (
        f"{NOTION_AUTH_URL}"
        f"?client_id={NOTION_CLIENT_ID}"
        f"&response_type=code"
        f"&owner=user"
        f"&redirect_uri={NOTION_REDIRECT_URI}"
    )
    
    return {"auth_url": auth_url}


@router.post("/oauth/callback")
async def notion_oauth_callback(data: NotionOAuthCallback, uid: str = Depends(get_current_user_uid)):
    """Handle Notion OAuth callback and exchange code for access token"""
    
    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        response = await client.post(
            NOTION_TOKEN_URL,
            auth=(NOTION_CLIENT_ID, NOTION_CLIENT_SECRET),
            json={
                "grant_type": "authorization_code",
                "code": data.code,
                "redirect_uri": NOTION_REDIRECT_URI
            }
        )
        
        if response.status_code != 200:
            logger.error(f"Failed to exchange Notion OAuth code: {response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to connect to Notion"
            )
        
        token_data = response.json()
        access_token = token_data.get("access_token")
        workspace_id = token_data.get("workspace_id")
        workspace_name = token_data.get("workspace_name")
        bot_id = token_data.get("bot_id")
    
    # Store the access token temporarily (will be saved when database is selected)
    async with async_session_maker() as session:
        try:
            # Check if integration already exists
            result = await session.execute(
                text("SELECT id FROM notion_integrations WHERE form_id = :form_id"),
                {"form_id": data.form_id}
            )
            existing = result.fetchone()
            
            if existing:
                # Update existing
                await session.execute(
                    text("""
                        UPDATE notion_integrations
                        SET access_token = :access_token, workspace_id = :workspace_id,
                            workspace_name = :workspace_name, bot_id = :bot_id,
                            updated_at = NOW()
                        WHERE form_id = :form_id
                    """),
                    {
                        "access_token": access_token,
                        "workspace_id": workspace_id,
                        "workspace_name": workspace_name,
                        "bot_id": bot_id,
                        "form_id": data.form_id
                    }
                )
            else:
                # Insert new (will need database_id later)
                await session.execute(
                    text("""
                        INSERT INTO notion_integrations
                        (form_id, user_id, access_token, workspace_id, workspace_name, bot_id, database_id)
                        VALUES (:form_id, :user_id, :access_token, :workspace_id, :workspace_name, :bot_id, '')
                    """),
                    {
                        "form_id": data.form_id,
                        "user_id": uid,
                        "access_token": access_token,
                        "workspace_id": workspace_id,
                        "workspace_name": workspace_name,
                        "bot_id": bot_id
                    }
                )
            
            await session.commit()
            
            # Fetch databases
            databases = await get_notion_databases(access_token)
            
            return {
                "success": True,
                "workspace_name": workspace_name,
                "databases": databases
            }
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Error saving Notion OAuth: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to save Notion connection"
            )


@router.get("/oauth/callback")
async def notion_oauth_callback_get(
    code: Optional[str] = Query(None),
    form_id: Optional[int] = Query(None),
    redirect: Optional[str] = Query(None, description="Optional frontend URL to redirect to with code appended")
):
    """
    Handle Notion OAuth browser redirect (GET).
    This endpoint does NOT finalize the connection server-side. It passes the `code` back to the frontend,
    which then calls the POST /api/notion/oauth/callback with Authorization to securely save the integration.

    Behavior:
    - If `redirect` is provided and safe, redirect to it with ?code=...&form_id=...
    - Else, render a tiny HTML page that postMessages the code to window.opener then closes the window.
    """
    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OAuth code")

    # Optional: validate redirect host to prevent open redirect
    def _is_allowed_redirect(url: str) -> bool:
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                return False
            host = (p.netloc or "").lower()
            for allowed in ALLOWED_OAUTH_REDIRECT_HOSTS:
                allowed = allowed.strip().lower()
                if not allowed:
                    continue
                if host == allowed or host.endswith("." + allowed):
                    return True
            return False
        except Exception:
            return False

    if redirect and _is_allowed_redirect(redirect):
        from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
        parsed = list(urlparse(redirect))
        q = dict(parse_qsl(parsed[4]))
        q.update({"code": code})
        if form_id is not None:
            q["form_id"] = str(form_id)
        parsed[4] = urlencode(q)
        return RedirectResponse(url=urlunparse(parsed), status_code=302)

    # Fallback: small HTML that informs the opener and closes
    html = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset='utf-8'/>
        <title>Connecting Notion…</title>
        <style>
          body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Helvetica Neue', Arial, sans-serif; margin: 20px; }}
          .card {{ max-width: 520px; margin: 40px auto; padding: 16px; border: 1px solid #e5e7eb; border-radius: 12px; }}
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Notion authorization received</h2>
          <p>You can close this window. Returning to the app…</p>
        </div>
        <script>
          (function() {{
            try {{
              if (window.opener) {{
                window.opener.postMessage({{ provider: 'notion', code: {code!r}, form_id: {form_id!r} }}, '*');
              }}
              setTimeout(function() {{ window.close(); }}, 300);
            }} catch(e) {{
              console.error(e);
            }}
          }})();
        </script>
      </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=200)


@router.post("/database/select")
async def select_notion_database(data: NotionDatabaseSelect, uid: str = Depends(get_current_user_uid)):
    """Select a Notion database and save field mappings"""
    async with async_session_maker() as session:
        try:
            # Update database selection and field mappings
            await session.execute(
                text("""
                    UPDATE notion_integrations
                    SET database_id = :database_id, database_name = :database_name,
                        field_mappings = :field_mappings, enabled = true, updated_at = NOW()
                    WHERE form_id = :form_id AND user_id = :user_id
                """),
                {
                    "database_id": data.database_id,
                    "database_name": data.database_name,
                    "field_mappings": json.dumps(data.field_mappings),
                    "form_id": data.form_id,
                    "user_id": uid
                }
            )
            
            await session.commit()
            
            return {"success": True, "message": "Notion database connected successfully"}
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Error selecting Notion database: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to connect database"
            )


@router.get("/integration/{form_id}", response_model=Optional[NotionIntegrationResponse])
async def get_notion_integration(form_id: int, uid: str = Depends(get_current_user_uid)):
    """Get Notion integration details for a form"""
    async with async_session_maker() as session:
        try:
            result = await session.execute(
                text("""
                    SELECT database_id, database_name, field_mappings, enabled, workspace_name
                    FROM notion_integrations
                    WHERE form_id = :form_id AND user_id = :user_id
                """),
                {"form_id": form_id, "user_id": uid}
            )
            row = result.fetchone()
            
            if not row:
                return None
            
            return {
                "form_id": form_id,
                "database_id": row[0],
                "database_name": row[1],
                "field_mappings": row[2] or {},
                "enabled": row[3],
                "workspace_name": row[4]
            }
            
        except Exception as e:
            logger.error(f"Error fetching Notion integration: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to fetch integration"
            )


@router.delete("/integration/{form_id}")
async def delete_notion_integration(form_id: int, uid: str = Depends(get_current_user_uid)):
    """Disconnect Notion integration"""
    async with async_session_maker() as session:
        try:
            await session.execute(
                text("DELETE FROM notion_integrations WHERE form_id = :form_id AND user_id = :user_id"),
                {"form_id": form_id, "user_id": uid}
            )
            await session.commit()
            
            return {"success": True, "message": "Notion integration disconnected"}
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Error deleting Notion integration: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to disconnect integration"
            )


@router.post("/sync/{form_id}")
async def sync_to_notion(form_id: int, submission_data: Dict[str, Any]):
    """
    Internal endpoint to sync form submission to Notion
    Called by the form submission handler
    """
    async with async_session_maker() as session:
        try:
            # Get integration details
            result = await session.execute(
                text("""
                    SELECT access_token, database_id, field_mappings, enabled
                    FROM notion_integrations
                    WHERE form_id = :form_id
                """),
                {"form_id": form_id}
            )
            row = result.fetchone()
            
            if not row or not row[3]:  # Not configured or disabled
                return {"success": False, "message": "Notion integration not enabled"}
            
            access_token = row[0]
            database_id = row[1]
            field_mappings = row[2] or {}
            
            # Build Notion properties from submission data
            notion_properties = {}
            
            for field_id, notion_property_name in field_mappings.items():
                field_value = submission_data.get(field_id)
                
                if field_value is not None:
                    # Convert to Notion property format (rich_text for now, can be enhanced)
                    notion_properties[notion_property_name] = {
                        "rich_text": [{"text": {"content": str(field_value)}}]
                    }
            
            # Create page in Notion
            await create_notion_page(access_token, database_id, notion_properties)
            
            logger.info(f"Successfully synced form {form_id} submission to Notion")
            return {"success": True, "message": "Synced to Notion"}
            
        except Exception as e:
            logger.error(f"Error syncing to Notion: {e}")
            return {"success": False, "message": str(e)}
