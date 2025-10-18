from fastapi import APIRouter, HTTPException, UploadFile, File, Request
from typing import Optional, Dict, Any
import io
import logging
import os
import requests

# Rate limiter
try:
    from utils.limiter import limiter
except Exception:
    from utils.limiter import limiter

logger = logging.getLogger("backend.virus_scan")

router = APIRouter(prefix="/api/virus-scan", tags=["virus-scan"])

# Cloudmersive API settings
CLOUDMERSIVE_API_KEY = os.getenv("CLOUDMERSIVE_API_KEY")
CLOUDMERSIVE_API_URL = "https://api.cloudmersive.com/virus/scan/file"

# Max file size for scanning (100MB default)
MAX_SCAN_SIZE = int(os.getenv("MAX_VIRUS_SCAN_SIZE", str(100 * 1024 * 1024)))


def _check_api_available() -> bool:
    """Check if Cloudmersive API key is configured."""
    return CLOUDMERSIVE_API_KEY is not None and len(CLOUDMERSIVE_API_KEY.strip()) > 0


def _scan_bytes(data: bytes, filename: str) -> Dict[str, Any]:
    """
    Scan bytes for viruses using Cloudmersive API.
    
    Returns:
        dict with keys: clean (bool), virus_name (str|None), scan_result (str)
    """
    if not data:
        return {
            "clean": True,
            "virus_name": None,
            "scan_result": "Empty file"
        }
    
    if not _check_api_available():
        logger.warning("Cloudmersive API key not configured")
        return {
            "clean": True,
            "virus_name": None,
            "scan_result": "Virus scanning not configured (development mode)",
            "warning": "API key not available"
        }
    
    try:
        # Prepare the file for upload to Cloudmersive
        files = {'inputFile': (filename, io.BytesIO(data))}
        headers = {'Apikey': CLOUDMERSIVE_API_KEY}
        
        # Make API request
        response = requests.post(
            CLOUDMERSIVE_API_URL,
            files=files,
            headers=headers,
            timeout=30
        )
        
        if response.status_code != 200:
            logger.error(f"Cloudmersive API error: {response.status_code} - {response.text}")
            raise HTTPException(
                status_code=502,
                detail="Virus scanning service error"
            )
        
        result = response.json()
        
        # Cloudmersive response format:
        # {
        #   "CleanResult": true/false,
        #   "FoundViruses": [{"FileName": "...", "VirusName": "..."}],
        #   "ContentInformation": {...}
        # }
        
        clean = result.get("CleanResult", False)
        found_viruses = result.get("FoundViruses", [])
        
        if clean:
            return {
                "clean": True,
                "virus_name": None,
                "scan_result": "No threats detected"
            }
        else:
            # Extract virus names
            virus_names = [v.get("VirusName", "Unknown") for v in found_viruses]
            virus_name = ", ".join(virus_names) if virus_names else "Malware"
            
            return {
                "clean": False,
                "virus_name": virus_name,
                "scan_result": f"Threat detected: {virus_name}"
            }
            
    except requests.exceptions.Timeout:
        logger.error("Cloudmersive API timeout")
        raise HTTPException(
            status_code=504,
            detail="Virus scan timeout"
        )
    except requests.exceptions.RequestException as e:
        logger.exception(f"Cloudmersive API request failed: {e}")
        raise HTTPException(
            status_code=502,
            detail="Virus scanning service unavailable"
        )
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
    Scan an uploaded file for viruses/malware using Cloudmersive API.
    
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
    
    # Perform virus scan with filename
    scan_result = _scan_bytes(data, file.filename or "unknown")
    
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
    Check if the Cloudmersive virus scanner is available and operational.
    
    Returns:
        {
            "available": bool,
            "provider": str,
            "status": str
        }
    """
    if not _check_api_available():
        return {
            "available": False,
            "provider": "Cloudmersive",
            "status": "API key not configured"
        }
    
    try:
        # Test API with a minimal request
        headers = {'Apikey': CLOUDMERSIVE_API_KEY}
        # Use a simple ping-like endpoint or the main endpoint with minimal data
        test_response = requests.get(
            "https://api.cloudmersive.com/validate/domain/check",
            headers=headers,
            timeout=5
        )
        
        if test_response.status_code in [200, 400, 404]:  # Any response means API is reachable
            return {
                "available": True,
                "provider": "Cloudmersive",
                "status": "operational"
            }
        else:
            return {
                "available": False,
                "provider": "Cloudmersive",
                "status": f"API error: {test_response.status_code}"
            }
    except requests.exceptions.Timeout:
        return {
            "available": False,
            "provider": "Cloudmersive",
            "status": "API timeout"
        }
    except Exception as e:
        return {
            "available": False,
            "provider": "Cloudmersive",
            "status": f"Error: {str(e)}"
        }
