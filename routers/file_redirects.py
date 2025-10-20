"""
File Redirect API
Provides short links for files to avoid displaying full R2 URLs in submissions
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import text
import secrets

try:
    from db.database import async_session_maker  # type: ignore
except Exception:
    from ..db.database import async_session_maker  # type: ignore

router = APIRouter()


def generate_short_id(length: int = 8) -> str:
    """Generate a random short ID for file redirect"""
    return secrets.token_urlsafe(length)[:length].replace('-', '').replace('_', '')


async def create_file_redirect(r2_key: str, form_id: str, response_id: str = None, file_type: str = 'upload') -> str:
    """
    Create a short link redirect for a file
    Returns the short ID (e.g., 'abc123')
    """
    short_id = generate_short_id()
    
    async with async_session_maker() as session:
        await session.execute(
            text("""
                INSERT INTO file_redirects (id, r2_key, form_id, response_id, file_type)
                VALUES (:id, :r2_key, :form_id, :response_id, :file_type)
                ON CONFLICT (id) DO NOTHING
            """),
            {
                'id': short_id,
                'r2_key': r2_key,
                'form_id': form_id,
                'response_id': response_id,
                'file_type': file_type
            }
        )
        await session.commit()
    
    return short_id


def get_short_url(short_id: str, base_url: str = None) -> str:
    """
    Get the full short URL for a file
    base_url defaults to current domain if not provided
    """
    if not base_url:
        # Will be replaced with actual domain in production
        base_url = ""
    return f"{base_url}/f/{short_id}"


@router.get('/f/{short_id}')
async def redirect_to_file(short_id: str):
    """
    Redirect short file link to actual R2 URL
    Example: /f/abc123 -> https://pub-xxx.r2.dev/files/...
    """
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                text("""
                    SELECT r2_key FROM file_redirects
                    WHERE id = :short_id
                """),
                {'short_id': short_id}
            )
            row = result.fetchone()
            
            if not row:
                raise HTTPException(status_code=404, detail="File not found")
            
            r2_key = row[0]
            
            # Build R2 public URL
            import os
            r2_public_domain = os.getenv('R2_PUBLIC_DOMAIN', 'pub-58c2396dc60040c28c260ed9e9405659.r2.dev')
            r2_url = f"https://{r2_public_domain}/{r2_key}"
            
            # Return permanent redirect to R2 URL
            return RedirectResponse(url=r2_url, status_code=301)
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error redirecting file: {e}")
        raise HTTPException(status_code=500, detail="Failed to redirect to file")
