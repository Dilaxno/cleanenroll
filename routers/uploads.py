from fastapi import APIRouter, HTTPException, UploadFile, File, Request
from typing import Optional
import io
import uuid
import logging

# Rate limiter (shared)
try:
    from utils.limiter import limiter  # type: ignore
except Exception:  # pragma: no cover
    from utils.limiter import limiter  # type: ignore

# Reuse R2 client and URL helpers from builder router to keep config in one place
try:
    from routers.builder import _r2_client, _public_url_for_key, R2_BUCKET  # type: ignore
except Exception:  # pragma: no cover
    from routers.builder import _r2_client, _public_url_for_key, R2_BUCKET  # type: ignore

# Optional MIME sniffer (python-magic). On Windows, prefer python-magic-bin.
try:
    import magic  # type: ignore
    _MAGIC_AVAILABLE = True
except Exception:  # pragma: no cover
    magic = None  # type: ignore
    _MAGIC_AVAILABLE = False

# Pillow for safe image decode/encode
try:
    from PIL import Image, UnidentifiedImageError  # type: ignore
    _PIL_AVAILABLE = True
except Exception:  # pragma: no cover
    Image = None  # type: ignore
    UnidentifiedImageError = Exception  # type: ignore
    _PIL_AVAILABLE = False

logger = logging.getLogger("backend.uploads")

router = APIRouter(prefix="/api/uploads", tags=["uploads"]) 

# Conservative allow-list for images
_ALLOWED_IMAGE_MIMES = {
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",  # will be re-encoded to PNG/JPEG (first frame)
}

# Guard against decompression bombs
if _PIL_AVAILABLE:
    try:
        # ~64 MPx upper-bound
        Image.MAX_IMAGE_PIXELS = 64_000_000
    except Exception:
        pass


def _sniff_mime(data: bytes) -> Optional[str]:
    if not data:
        return None
    if _MAGIC_AVAILABLE:
        try:
            m = magic.Magic(mime=True)  # type: ignore
            return str(m.from_buffer(data[:8192]) or "").strip() or None
        except Exception:
            return None
    # Fallback: very rough heuristic when magic is unavailable
    try:
        if data.startswith(b"\xFF\xD8\xFF"):
            return "image/jpeg"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return "image/webp"
        if data[:6] in (b"GIF87a", b"GIF89a"):
            return "image/gif"
    except Exception:
        pass
    return None


def _sanitize_image_bytes(data: bytes) -> tuple[bytes, str, str]:
    """
    Decode the image with Pillow (strips metadata), re-encode to a safe format,
    and return (sanitized_bytes, content_type, ext).

    - Preserves alpha by choosing PNG when transparency is present.
    - Otherwise uses JPEG with sane defaults (quality 85, progressive, no EXIF).
    - For animated GIF/WebP, uses the first frame only (static sanitize).
    """
    if not _PIL_AVAILABLE or Image is None:
        raise HTTPException(status_code=500, detail="Image library not available on server")
    try:
        bio = io.BytesIO(data)
        with Image.open(bio) as im:
            # Ensure full decode
            try:
                im.load()
            except Exception:
                pass
            # Normalize mode and pick output format
            has_alpha = (
                (im.mode in ("RGBA", "LA")) or
                ("transparency" in getattr(im, "info", {}))
            )
            is_palette = im.mode == "P"

            # Use first frame for animated formats
            try:
                if getattr(im, "is_animated", False) and getattr(im, "n_frames", 1) > 1:
                    im.seek(0)
            except Exception:
                pass

            out = io.BytesIO()
            if has_alpha or is_palette:
                # Preserve transparency via PNG
                if im.mode not in ("RGBA", "LA"):
                    try:
                        im = im.convert("RGBA")
                    except Exception:
                        im = im.convert("RGB")
                im.save(out, format="PNG", optimize=True)
                return out.getvalue(), "image/png", ".png"
            else:
                # JPEG without EXIF, sane quality
                if im.mode not in ("RGB", "L"):
                    im = im.convert("RGB")
                im.save(out, format="JPEG", quality=85, optimize=True, progressive=True, subsampling="4:2:0")
                return out.getvalue(), "image/jpeg", ".jpg"
    except UnidentifiedImageError:
        raise HTTPException(status_code=415, detail="Unsupported or corrupted image")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("sanitize image failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to process image")


def _safe_key(base_dir: str, ext: str) -> str:
    base = base_dir.strip("/") if base_dir else "uploads/images"
    uid = uuid.uuid4().hex
    return f"{base}/{uid}{ext}"


@router.post("/image")
@limiter.limit("60/minute")
async def upload_sanitized_image(request: Request, file: UploadFile = File(...), folder: Optional[str] = None):
    """
    Upload an image after server-side sanitization:
      - Verify MIME type from bytes using python-magic (or fallback heuristic)
      - Re-encode with Pillow to strip EXIF and possible malicious data
      - Keep processing in-memory with BytesIO (no temp files)
      - Upload sanitized bytes to Cloudflare R2

    Returns: { publicUrl, key, contentType, bytes }
    """
    # Verify authentication for secure uploads
    try:
        from firebase_admin import auth as _admin_auth
        authz = request.headers.get("authorization") or request.headers.get("Authorization")
        if not authz or not authz.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Authentication required")
        token = authz.split(" ", 1)[1].strip()
        decoded = _admin_auth.verify_id_token(token)
        if not decoded.get("uid"):
            raise HTTPException(status_code=401, detail="Invalid token")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Auth verification failed: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")
    
    # Read into memory
    try:
        data = await file.read()
    except Exception:
        data = b""
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")

    # Enforce a reasonable upload cap for images (20MB pre-sanitize)
    MAX_BYTES = 20 * 1024 * 1024
    if len(data) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    sniffed = _sniff_mime(data)
    if not sniffed or not sniffed.startswith("image/"):
        raise HTTPException(status_code=415, detail="Only image uploads are allowed")
    
    # Handle SVG separately - sanitize to prevent XSS
    if sniffed == "image/svg+xml" or data.strip().startswith(b"<svg") or data.strip().startswith(b"<?xml"):
        # Basic SVG sanitization: remove script tags and event handlers
        try:
            svg_text = data.decode('utf-8', errors='ignore')
            # Remove dangerous elements and attributes
            import re
            # Remove script tags
            svg_text = re.sub(r'<script[^>]*>.*?</script>', '', svg_text, flags=re.IGNORECASE | re.DOTALL)
            # Remove event handlers (onclick, onload, etc.)
            svg_text = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', svg_text, flags=re.IGNORECASE)
            svg_text = re.sub(r'\s+on\w+\s*=\s*[^\s>]+', '', svg_text, flags=re.IGNORECASE)
            # Remove javascript: hrefs
            svg_text = re.sub(r'href\s*=\s*["\']javascript:[^"\']*["\']', '', svg_text, flags=re.IGNORECASE)
            sanitized = svg_text.encode('utf-8')
            content_type = "image/svg+xml"
            ext = ".svg"
        except Exception as e:
            logger.exception("SVG sanitization failed: %s", e)
            raise HTTPException(status_code=415, detail="Invalid SVG file")
    elif sniffed not in _ALLOWED_IMAGE_MIMES:
        # We'll still attempt to decode/encode with Pillow; block if Pillow fails
        logger.info("upload: non-allowlisted image mime=%s; attempting sanitize", sniffed)
        # Re-encode and strip metadata
        sanitized, content_type, ext = _sanitize_image_bytes(data)
    else:
        # Re-encode and strip metadata
        sanitized, content_type, ext = _sanitize_image_bytes(data)

    # Persist to R2 with contentType derived from sanitized output
    key = _safe_key(folder or "uploads/images", ext)
    try:
        s3 = _r2_client()
        s3.put_object(Bucket=R2_BUCKET, Key=key, Body=sanitized, ContentType=content_type)
        url = _public_url_for_key(key)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("R2 put_object failed key=%s", key)
        raise HTTPException(status_code=502, detail=f"Upload failed: {e}")

    return {"publicUrl": url, "key": key, "contentType": content_type, "bytes": len(sanitized)}
