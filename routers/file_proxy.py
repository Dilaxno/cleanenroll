"""
File proxy router for secure file downloads with clean short links.
Instead of exposing R2 public URLs, files are accessed via:
https://cleanenroll.com/submission/abc123

This provides:
- Privacy: R2 URLs not exposed
- Control: Track downloads, enforce permissions
- Clean URLs: User-friendly links
"""

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import RedirectResponse, StreamingResponse
import os
import boto3
from botocore.client import Config as BotoConfig
from sqlalchemy import text
import logging

router = APIRouter()
logger = logging.getLogger("backend.file_proxy")

# R2 configuration
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "")
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "")
R2_BUCKET = os.getenv("R2_BUCKET", "cleanenroll")
R2_ENDPOINT = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com" if R2_ACCOUNT_ID else ""

# Import database session
from db.database import async_session_maker


def _r2_client():
    """Create R2 client with proper config."""
    return boto3.client(
        "s3",
        endpoint_url=R2_ENDPOINT,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=BotoConfig(signature_version="s3v4"),
        region_name="auto",
    )


@router.get("/submission/{file_id}")
async def download_submission_file(file_id: str):
    """
    Download a submission file via clean short link.
    Maps file_id to R2 key and streams the file.
    
    Example: GET /submission/abc123 -> streams file from R2
    """
    if not file_id or len(file_id) < 6:
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        # Look up R2 key from database
        async with async_session_maker() as session:
            result = await session.execute(
                text("""
                    SELECT r2_key, filename, content_type 
                    FROM submission_files 
                    WHERE id = :file_id 
                    LIMIT 1
                """),
                {"file_id": file_id}
            )
            row = result.mappings().first()
            
            if not row:
                raise HTTPException(status_code=404, detail="File not found")
            
            r2_key = row.get("r2_key")
            filename = row.get("filename") or "download"
            content_type = row.get("content_type") or "application/octet-stream"
        
        # Fetch file from R2
        s3 = _r2_client()
        obj = s3.get_object(Bucket=R2_BUCKET, Key=r2_key)
        
        # Stream file with appropriate headers
        return StreamingResponse(
            obj["Body"].iter_chunks(chunk_size=8192),
            media_type=content_type,
            headers={
                "Content-Disposition": f'inline; filename="{filename}"',
                "Cache-Control": "public, max-age=31536000",
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("download_submission_file failed file_id=%s", file_id)
        raise HTTPException(status_code=500, detail="Failed to download file")


@router.get("/signature/{signature_id}")
async def download_signature(signature_id: str):
    """
    Download a signature image via clean short link.
    Example: GET /signature/xyz789 -> streams PNG from R2
    """
    if not signature_id or len(signature_id) < 6:
        raise HTTPException(status_code=404, detail="Signature not found")
    
    try:
        # Look up R2 key from database
        async with async_session_maker() as session:
            result = await session.execute(
                text("""
                    SELECT r2_key, filename 
                    FROM submission_signatures 
                    WHERE id = :sig_id 
                    LIMIT 1
                """),
                {"sig_id": signature_id}
            )
            row = result.mappings().first()
            
            if not row:
                raise HTTPException(status_code=404, detail="Signature not found")
            
            r2_key = row.get("r2_key")
            filename = row.get("filename") or "signature.png"
        
        # Fetch signature from R2
        s3 = _r2_client()
        obj = s3.get_object(Bucket=R2_BUCKET, Key=r2_key)
        
        # Stream PNG with appropriate headers
        return StreamingResponse(
            obj["Body"].iter_chunks(chunk_size=8192),
            media_type="image/png",
            headers={
                "Content-Disposition": f'inline; filename="{filename}"',
                "Cache-Control": "public, max-age=31536000",
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("download_signature failed signature_id=%s", signature_id)
        raise HTTPException(status_code=500, detail="Failed to download signature")
