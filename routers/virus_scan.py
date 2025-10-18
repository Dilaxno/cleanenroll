from fastapi import APIRouter, HTTPException, UploadFile, File, Request
from typing import Optional, Dict, Any
import io
import logging
import tempfile
import os

# Rate limiter
try:
    from utils.limiter import limiter
except Exception:
    from utils.limiter import limiter

# ClamAV Python client
try:
    import clamd
    _CLAMD_AVAILABLE = True
except Exception:
    clamd = None
    _CLAMD_AVAILABLE = False

logger = logging.getLogger("backend.virus_scan")

router = APIRouter(prefix="/api/virus-scan", tags=["virus-scan"])

# ClamAV connection settings
CLAMD_HOST = os.getenv("CLAMD_HOST", "localhost")
CLAMD_PORT = int(os.getenv("CLAMD_PORT", "3310"))
CLAMD_SOCKET = os.getenv("CLAMD_SOCKET")  # Unix socket path if preferred

# Max file size for scanning (100MB default)
MAX_SCAN_SIZE = int(os.getenv("MAX_VIRUS_SCAN_SIZE", str(100 * 1024 * 1024)))


def _get_clamd_client():
    """Get ClamAV daemon client connection."""
    if not _CLAMD_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="ClamAV client library not available"
        )
    
    try:
        # Try Unix socket first if configured
        if CLAMD_SOCKET and os.path.exists(CLAMD_SOCKET):
            cd = clamd.ClamdUnixSocket(CLAMD_SOCKET)
        else:
            # Fall back to TCP connection
            cd = clamd.ClamdNetworkSocket(host=CLAMD_HOST, port=CLAMD_PORT)
        
        # Test connection
        cd.ping()
        return cd
    except Exception as e:
        logger.error(f"Failed to connect to ClamAV daemon: {e}")
        raise HTTPException(
            status_code=503,
            detail=f"Virus scanning service unavailable: {e}"
        )


def _scan_bytes(data: bytes) -> Dict[str, Any]:
    """
    Scan bytes for viruses using ClamAV.
    
    Returns:
        dict with keys: clean (bool), virus_name (str|None), scan_result (str)
    """
    if not data:
        return {
            "clean": True,
            "virus_name": None,
            "scan_result": "Empty file"
        }
    
    cd = _get_clamd_client()
    
    try:
        # Scan the data buffer
        result = cd.instream(io.BytesIO(data))
        
        # Result format: {'stream': ('FOUND', 'Eicar-Test-Signature')} or {'stream': ('OK', None)}
        stream_result = result.get('stream', ('ERROR', 'Unknown'))
        status, details = stream_result
        
        if status == 'OK':
            return {
                "clean": True,
                "virus_name": None,
                "scan_result": "No threats detected"
            }
        elif status == 'FOUND':
            return {
                "clean": False,
                "virus_name": details,
                "scan_result": f"Threat detected: {details}"
            }
        else:
            logger.warning(f"ClamAV scan returned unexpected status: {status}")
            return {
                "clean": False,
                "virus_name": None,
                "scan_result": f"Scan error: {status}"
            }
            
    except Exception as e:
        logger.exception(f"Error during virus scan: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Virus scan failed: {str(e)}"
        )


@router.post("/scan-file")
@limiter.limit("30/minute")
async def scan_file_for_viruses(
    request: Request,
    file: UploadFile = File(...)
) -> Dict[str, Any]:
    """
    Scan an uploaded file for viruses/malware using ClamAV.
    
    This endpoint provides real-time virus scanning before file upload.
    Returns scan results including whether the file is clean or infected.
    
    Returns:
        {
            "clean": bool,
            "virus_name": str | None,
            "scan_result": str,
            "file_name": str,
            "file_size": int
        }
    """
    if not _CLAMD_AVAILABLE:
        logger.warning("ClamAV scanning requested but library not available")
        # In development/testing, you might want to skip and return clean
        # For production, you should enforce scanning
        return {
            "clean": True,
            "virus_name": None,
            "scan_result": "Virus scanning not configured (development mode)",
            "file_name": file.filename,
            "file_size": 0,
            "warning": "ClamAV not available"
        }
    
    # Read file data
    try:
        data = await file.read()
        file_size = len(data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")
    
    # Check size limit
    if file_size > MAX_SCAN_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large for virus scanning (max: {MAX_SCAN_SIZE // (1024*1024)}MB)"
        )
    
    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    
    # Perform virus scan
    scan_result = _scan_bytes(data)
    
    # Add file metadata
    scan_result["file_name"] = file.filename or "unknown"
    scan_result["file_size"] = file_size
    
    # Log security events
    if not scan_result["clean"]:
        logger.warning(
            f"VIRUS DETECTED: {scan_result['virus_name']} in file {file.filename} "
            f"(size: {file_size} bytes) from IP: {request.client.host if request.client else 'unknown'}"
        )
    else:
        logger.info(f"Clean scan: {file.filename} ({file_size} bytes)")
    
    return scan_result


@router.get("/health")
async def check_scanner_health() -> Dict[str, Any]:
    """
    Check if the ClamAV virus scanner is available and operational.
    
    Returns:
        {
            "available": bool,
            "version": str | None,
            "status": str
        }
    """
    if not _CLAMD_AVAILABLE:
        return {
            "available": False,
            "version": None,
            "status": "ClamAV Python client not installed"
        }
    
    try:
        cd = _get_clamd_client()
        version = cd.version()
        return {
            "available": True,
            "version": version,
            "status": "operational"
        }
    except HTTPException as e:
        return {
            "available": False,
            "version": None,
            "status": str(e.detail)
        }
    except Exception as e:
        return {
            "available": False,
            "version": None,
            "status": f"Error: {str(e)}"
        }
