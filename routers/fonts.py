from fastapi import APIRouter, HTTPException, UploadFile, File, Request, Depends
from typing import Optional, List
import uuid
import logging
from pydantic import BaseModel

# Rate limiter
try:
    from utils.limiter import limiter
except Exception:
    from utils.limiter import limiter

# R2 client and helpers
try:
    from routers.builder import _r2_client, _public_url_for_key, R2_BUCKET
except Exception:
    from routers.builder import _r2_client, _public_url_for_key, R2_BUCKET

# Database connection
try:
    from db.database import async_session_maker
except Exception:
    from db.database import async_session_maker

from sqlalchemy import text

# Firebase Admin for token verification
try:
    import firebase_admin
    from firebase_admin import auth as fb_auth
    _FB_AVAILABLE = True
except Exception:
    _FB_AVAILABLE = False

logger = logging.getLogger("backend.fonts")
router = APIRouter(prefix="/api/uploads/fonts", tags=["fonts"])

# Allowed font formats with their MIME types
ALLOWED_FONT_FORMATS = {
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ttf": "font/ttf",
    ".otf": "font/otf"
}

# Max font file size: 5MB
MAX_FONT_SIZE = 5 * 1024 * 1024


class FontUploadResponse(BaseModel):
    id: str
    font_name: str
    font_url: str
    font_format: str
    file_size: int


class FontListItem(BaseModel):
    id: str
    font_name: str
    font_url: str
    font_format: str
    file_size: int
    created_at: str


async def _get_uid_from_token(request: Request) -> str:
    """Extract and verify Firebase ID token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = auth_header.replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    
    if not _FB_AVAILABLE:
        raise HTTPException(status_code=500, detail="Authentication not available")
    
    try:
        decoded = fb_auth.verify_id_token(token)
        uid = decoded.get("uid")
        if not uid:
            raise HTTPException(status_code=401, detail="Invalid token")
        return uid
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@router.post("/upload", response_model=FontUploadResponse)
@limiter.limit("30/minute")
async def upload_font(
    request: Request,
    file: UploadFile = File(...),
    font_name: Optional[str] = None
):
    """
    Upload a custom font file (.woff2, .woff, .ttf, .otf) to R2 storage.
    Returns font metadata including public URL.
    """
    uid = await _get_uid_from_token(request)
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Read file
    try:
        data = await file.read()
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to read file")
    
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    
    # Check file size
    if len(data) > MAX_FONT_SIZE:
        raise HTTPException(status_code=413, detail="Font file too large (max 5MB)")
    
    # Get file extension
    filename = file.filename or ""
    ext = None
    for allowed_ext in ALLOWED_FONT_FORMATS.keys():
        if filename.lower().endswith(allowed_ext):
            ext = allowed_ext
            break
    
    if not ext:
        raise HTTPException(
            status_code=415,
            detail="Unsupported font format. Allowed: .woff2, .woff, .ttf, .otf"
        )
    
    # Determine font format and content type
    font_format = ext.lstrip(".")
    content_type = ALLOWED_FONT_FORMATS[ext]
    
    # Generate unique font ID and R2 key
    font_id = uuid.uuid4().hex
    r2_key = f"fonts/{uid}/{font_id}{ext}"
    
    # Upload to R2 with proper headers
    try:
        s3 = _r2_client()
        s3.put_object(
            Bucket=R2_BUCKET,
            Key=r2_key,
            Body=data,
            ContentType=content_type,
            # Set CORS header for cross-origin font loading
            ContentDisposition="inline",
            CacheControl="public, max-age=31536000"  # 1 year cache
        )
        font_url = _public_url_for_key(r2_key)
    except Exception as e:
        logger.exception("R2 font upload failed: %s", e)
        raise HTTPException(status_code=502, detail="Upload failed")
    
    # Store metadata in database
    font_display_name = font_name or filename.rsplit(".", 1)[0]
    
    try:
        async with async_session_maker() as session:
            await session.execute(
                text("""
                INSERT INTO custom_fonts (id, user_id, font_name, font_url, font_format, file_size)
                VALUES (:id, :user_id, :font_name, :font_url, :font_format, :file_size)
                """),
                {
                    "id": font_id,
                    "user_id": uid,
                    "font_name": font_display_name,
                    "font_url": font_url,
                    "font_format": font_format,
                    "file_size": len(data)
                }
            )
            await session.commit()
    except Exception as e:
        logger.exception("Database insert failed: %s", e)
        # Try to clean up R2 upload
        try:
            s3.delete_object(Bucket=R2_BUCKET, Key=r2_key)
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Failed to save font metadata")
    
    return FontUploadResponse(
        id=font_id,
        font_name=font_display_name,
        font_url=font_url,
        font_format=font_format,
        file_size=len(data)
    )


@router.get("", response_model=List[FontListItem])
async def list_fonts(request: Request):
    """Get all custom fonts for the current user."""
    uid = await _get_uid_from_token(request)
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                text("""
                SELECT id, font_name, font_url, font_format, file_size, created_at
                FROM custom_fonts
                WHERE user_id = :user_id
                ORDER BY created_at DESC
                """),
                {"user_id": uid}
            )
            rows = result.fetchall()
            
            fonts = []
            for row in rows:
                fonts.append(FontListItem(
                    id=row[0],
                    font_name=row[1],
                    font_url=row[2],
                    font_format=row[3],
                    file_size=row[4],
                    created_at=str(row[5])
                ))
            
            return fonts
    except Exception as e:
        logger.exception("Failed to list fonts: %s", e)
        raise HTTPException(status_code=500, detail="Failed to list fonts")


@router.delete("/{font_id}")
async def delete_font(font_id: str, request: Request):
    """Delete a custom font (removes from both database and R2)."""
    uid = await _get_uid_from_token(request)
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        async with async_session_maker() as session:
            # Get font URL to extract R2 key
            result = await session.execute(
                text("SELECT font_url FROM custom_fonts WHERE id = :id AND user_id = :user_id"),
                {"id": font_id, "user_id": uid}
            )
            row = result.fetchone()
            
            if not row:
                raise HTTPException(status_code=404, detail="Font not found")
            
            font_url = row[0]
            
            # Delete from database
            await session.execute(
                text("DELETE FROM custom_fonts WHERE id = :id AND user_id = :user_id"),
                {"id": font_id, "user_id": uid}
            )
            await session.commit()
        
        # Try to delete from R2 (best effort)
        try:
            # Extract key from URL
            if "/fonts/" in font_url:
                key = font_url.split("/fonts/", 1)[1]
                key = f"fonts/{key}"
                s3 = _r2_client()
                s3.delete_object(Bucket=R2_BUCKET, Key=key)
        except Exception as e:
            logger.warning("Failed to delete font from R2: %s", e)
        
        return {"success": True, "message": "Font deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to delete font: %s", e)
        raise HTTPException(status_code=500, detail="Failed to delete font")
