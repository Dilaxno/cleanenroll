"""
Data normalization utilities for converting Neon DB responses to frontend-compatible formats.

Problem:
---------
PostgreSQL JSONB fields can sometimes return boolean values as strings ("true", "false") 
instead of actual Python booleans (True, False). This happens when:
1. Data was inserted as JSON strings instead of native types
2. JSONB is serialized/deserialized through different drivers
3. Mixing string and native boolean values in nested structures

When React receives {"enabled": "true"} instead of {"enabled": true}, strict equality 
checks like `if (enabled === true)` fail, breaking component logic.

Solution:
---------
This module provides recursive normalization functions that:
1. Convert string "true"/"false" to actual Python True/False
2. Preserve all other data types (numbers, strings, None, etc.)
3. Work recursively through nested dicts and lists
4. Apply to all data fetched from Neon DB before sending to frontend

Usage:
------
Apply normalize_booleans() to any data structure before returning from API endpoints:

    # For entire form objects
    form_data = dict(row)
    return normalize_booleans(form_data)
    
    # For lists of forms
    forms = [dict(row) for row in result.mappings().all()]
    return [normalize_booleans(form) for form in forms]
    
    # For specific JSONB fields
    theme = normalize_jsonb_field(row.get('theme'), default={})
"""
from typing import Any, Dict, List, Union
import json


def normalize_booleans(obj: Any) -> Any:
    """
    Recursively normalize boolean values in nested structures.
    Converts string "true"/"false" to actual Python booleans.
    
    This is critical for JSONB fields from PostgreSQL that may store
    booleans as strings, which break React component logic.
    
    Args:
        obj: Any object (dict, list, str, bool, etc.)
        
    Returns:
        Normalized object with all string booleans converted to actual booleans
        
    Examples:
        >>> normalize_booleans({"enabled": "true", "count": 5})
        {"enabled": True, "count": 5}
        
        >>> normalize_booleans(["true", "false", 123])
        [True, False, 123]
    """
    # Handle None
    if obj is None:
        return None
    
    # Handle string booleans
    if isinstance(obj, str):
        if obj.lower() == "true":
            return True
        elif obj.lower() == "false":
            return False
        return obj
    
    # Handle actual booleans (pass through)
    if isinstance(obj, bool):
        return obj
    
    # Handle numbers (pass through)
    if isinstance(obj, (int, float)):
        return obj
    
    # Recursively handle dictionaries
    if isinstance(obj, dict):
        return {k: normalize_booleans(v) for k, v in obj.items()}
    
    # Recursively handle lists/tuples
    if isinstance(obj, (list, tuple)):
        normalized = [normalize_booleans(item) for item in obj]
        return type(obj)(normalized)  # Preserve list vs tuple
    
    # Pass through other types (datetime, etc.)
    return obj


def normalize_jsonb_field(value: Any, default: Any = None) -> Any:
    """
    Safely parse and normalize a JSONB field from Neon DB.
    
    PostgreSQL can return JSONB as either:
    - Already parsed dict/list (via psycopg2/sqlalchemy)
    - JSON string that needs parsing
    - String boolean values that need conversion
    
    Args:
        value: Raw JSONB value from database
        default: Default value if parsing fails
        
    Returns:
        Normalized Python object with proper types
    """
    try:
        # Already a dict or list - just normalize booleans
        if isinstance(value, (dict, list)):
            return normalize_booleans(value)
        
        # String - try to parse as JSON first
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return normalize_booleans(parsed)
            except (json.JSONDecodeError, ValueError):
                # Not valid JSON - treat as string boolean or regular string
                return normalize_booleans(value)
        
        # None or other types
        return value if value is not None else default
        
    except Exception:
        return default


def normalize_db_row(row: Dict[str, Any], jsonb_fields: List[str] = None) -> Dict[str, Any]:
    """
    Normalize an entire database row, with special handling for JSONB fields.
    
    Args:
        row: Database row as dictionary
        jsonb_fields: List of field names that are JSONB columns (e.g., ['theme', 'fields', 'branding'])
        
    Returns:
        Fully normalized dictionary safe for JSON serialization to frontend
    """
    if jsonb_fields is None:
        jsonb_fields = ['theme', 'fields', 'branding', 'redirect', 'restricted_countries', 
                        'allowed_countries', 'data', 'answers', 'metadata']
    
    normalized = {}
    
    for key, value in row.items():
        if key in jsonb_fields:
            # Special JSONB normalization
            normalized[key] = normalize_jsonb_field(value, default={} if key in ['theme', 'branding', 'redirect', 'data', 'answers', 'metadata'] else [])
        else:
            # Regular field - just normalize booleans
            normalized[key] = normalize_booleans(value)
    
    return normalized
