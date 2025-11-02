"""
Geolocation utilities for IP address lookup
Supports Geoapify, IPInfo, and DbIpCity providers
"""
import os
import logging
import urllib.parse
import urllib.request
import json
from typing import Optional, Dict, Any

logger = logging.getLogger("backend.geo")

# API keys from environment
GEOAPIFY_API_KEY = os.getenv("GEOAPIFY_API_KEY") or ""
IPINFO_API_TOKEN = os.getenv("IPINFO_API_TOKEN") or ""

# Try to load DbIpCity as fallback
try:
    from ip2geotools.databases.noncommercial import DbIpCity
    _DBIPCITY_AVAILABLE = True
except Exception:
    DbIpCity = None
    _DBIPCITY_AVAILABLE = False

_GEOAPIFY_AVAILABLE = bool(GEOAPIFY_API_KEY)
_IPINFO_AVAILABLE = bool(IPINFO_API_TOKEN)


def get_geo_info(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get geolocation information for an IP address.
    Returns dict with: country_code, country, city, region, latitude, longitude
    Returns None if no geo data is available.
    """
    if not ip:
        return None
    
    # Try Geoapify first (most reliable)
    if _GEOAPIFY_AVAILABLE:
        try:
            url = (
                "https://api.geoapify.com/v1/ipinfo?"
                + urllib.parse.urlencode({"ip": ip, "apiKey": GEOAPIFY_API_KEY})
            )
            req = urllib.request.Request(url, headers={
                "User-Agent": "CleanEnroll/1.0 (+https://cleanenroll.com)",
                "Accept": "application/json"
            })
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                country_code = data.get('country', {}).get('iso_code')
                country = data.get('country', {}).get('name')
                city = data.get('city', {}).get('name')
                region = data.get('state', {}).get('name')
                
                location = data.get('location', {})
                latitude = location.get('latitude')
                longitude = location.get('longitude')
                
                return {
                    'country_code': country_code,
                    'country': country,
                    'city': city,
                    'region': region,
                    'latitude': float(latitude) if latitude else None,
                    'longitude': float(longitude) if longitude else None
                }
        except Exception as e:
            logger.debug(f"Geoapify lookup failed for {ip}: {str(e)}")
    
    # Try IPInfo as backup
    if _IPINFO_AVAILABLE:
        try:
            url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_TOKEN}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "CleanEnroll/1.0 (+https://cleanenroll.com)",
                "Accept": "application/json"
            })
            with urllib.request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                country_code = data.get('country')
                city = data.get('city')
                region = data.get('region')
                
                # Parse loc field (lat,lon)
                loc = data.get('loc', '')
                latitude, longitude = None, None
                if ',' in loc:
                    parts = loc.split(',')
                    if len(parts) == 2:
                        try:
                            latitude = float(parts[0])
                            longitude = float(parts[1])
                        except ValueError:
                            pass
                
                return {
                    'country_code': country_code,
                    'country': None,  # IPInfo doesn't provide full country name
                    'city': city,
                    'region': region,
                    'latitude': latitude,
                    'longitude': longitude
                }
        except Exception as e:
            logger.debug(f"IPInfo lookup failed for {ip}: {str(e)}")
    
    # Fallback to DbIpCity
    if _DBIPCITY_AVAILABLE and DbIpCity:
        try:
            res = DbIpCity.get(ip, api_key='free')
            country_code = getattr(res, 'country', None)
            city = getattr(res, 'city', None)
            region = getattr(res, 'region', None)
            
            latitude = None
            longitude = None
            try:
                latitude = float(getattr(res, "latitude", None)) if getattr(res, "latitude", None) is not None else None
                longitude = float(getattr(res, "longitude", None)) if getattr(res, "longitude", None) is not None else None
            except Exception:
                pass
            
            return {
                'country_code': country_code,
                'country': None,
                'city': city,
                'region': region,
                'latitude': latitude,
                'longitude': longitude
            }
        except Exception as e:
            logger.debug(f"DbIpCity lookup failed for {ip}: {str(e)}")
    
    return None
