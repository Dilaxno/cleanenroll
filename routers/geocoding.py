"""
Geocoding proxy router - proxies MapTiler geocoding requests to keep API key secure on backend.
"""
import os
import httpx
from fastapi import APIRouter, Request, HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/geocoding", tags=["geocoding"])
limiter = Limiter(key_func=get_remote_address)

MAPTILER_API_KEY = os.getenv("MAPTILER_API_KEY", "")

@router.get("/search")
@limiter.limit("60/minute")
async def geocoding_search(request: Request, q: str, language: str = "en", limit: int = 6):
    """
    Proxy endpoint for MapTiler geocoding search.
    Keeps the API key secure on the backend.
    
    Args:
        q: Search query (place name, address, etc.)
        language: Language code (e.g., 'en', 'es', 'fr')
        limit: Maximum number of results (default: 6)
    
    Returns:
        GeoJSON FeatureCollection with search results
    """
    if not MAPTILER_API_KEY:
        raise HTTPException(status_code=500, detail="MapTiler API key not configured")
    
    if not q or not q.strip():
        raise HTTPException(status_code=400, detail="Query parameter 'q' is required")
    
    # Sanitize inputs
    q = q.strip()[:200]  # Limit query length
    language = language[:5] if language else "en"
    limit = max(1, min(limit, 10))  # Clamp between 1-10
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            params = {
                "q": q,
                "language": language,
                "limit": str(limit),
                "key": MAPTILER_API_KEY
            }
            
            response = await client.get(
                f"https://api.maptiler.com/geocoding/{q}.json",
                params=params
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"MapTiler API error: {response.status_code}"
                )
            
            return response.json()
            
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Geocoding request timed out")
    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail=f"Geocoding service unavailable: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Geocoding error: {str(e)}")
