"""
Google reCAPTCHA Admin API Service
Handles domain-specific reCAPTCHA key provisioning for custom domains
"""
import os
import logging
from typing import Dict, Optional, Tuple
import httpx
from cryptography.fernet import Fernet
from sqlalchemy import text
from db.database import async_session_maker

logger = logging.getLogger(__name__)

# Environment variables
RECAPTCHA_ADMIN_API_KEY = os.getenv("RECAPTCHA_ADMIN_API_KEY", "")
RECAPTCHA_PROJECT_ID = os.getenv("RECAPTCHA_PROJECT_ID", "")
RECAPTCHA_API_BASE = "https://recaptchaenterprise.googleapis.com/v1"

# Encryption key for storing secret keys (must be 32 url-safe base64-encoded bytes)
ENCRYPTION_KEY = os.getenv("RECAPTCHA_ENCRYPTION_KEY", "")
if ENCRYPTION_KEY:
    cipher_suite = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)
else:
    cipher_suite = None
    logger.warning("RECAPTCHA_ENCRYPTION_KEY not set - secret keys will be stored unencrypted (NOT RECOMMENDED)")


def _encrypt_secret(secret: str) -> str:
    """Encrypt a reCAPTCHA secret key for secure storage."""
    if not cipher_suite:
        return secret
    return cipher_suite.encrypt(secret.encode()).decode()


def _decrypt_secret(encrypted_secret: str) -> str:
    """Decrypt a stored reCAPTCHA secret key."""
    if not cipher_suite:
        return encrypted_secret
    return cipher_suite.decrypt(encrypted_secret.encode()).decode()


async def create_recaptcha_key_for_domain(domain: str) -> Tuple[str, str]:
    """
    Create a new reCAPTCHA v2 site key for a specific domain using Admin API.
    
    Args:
        domain: The custom domain (e.g., 'forms.example.com')
        
    Returns:
        Tuple of (site_key, secret_key)
        
    Raises:
        Exception: If API key is not configured or API request fails
    """
    if not RECAPTCHA_ADMIN_API_KEY:
        raise Exception("RECAPTCHA_ADMIN_API_KEY not configured")
    
    if not RECAPTCHA_PROJECT_ID:
        raise Exception("RECAPTCHA_PROJECT_ID not configured")
    
    # Normalize domain
    domain = domain.strip().lower().strip('.')
    
    # Prepare API request
    url = f"{RECAPTCHA_API_BASE}/projects/{RECAPTCHA_PROJECT_ID}/keys"
    
    payload = {
        "displayName": f"CleanEnroll - {domain}",
        "labels": {
            "domain": domain,
            "service": "cleanenroll",
            "type": "custom-domain"
        },
        "webSettings": {
            "allowedDomains": [domain],
            "allowAmpTraffic": False,
            "integrationType": "CHECKBOX"  # reCAPTCHA v2 checkbox
        }
    }
    
    headers = {
        "Authorization": f"Bearer {RECAPTCHA_ADMIN_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            # Extract keys from response
            site_key = data.get("name", "").split("/")[-1]  # Extract key ID from resource name
            
            # Note: The Admin API doesn't return the secret key in create response
            # The secret is managed by Google and retrieved via separate API call
            # For now, we'll use the legacy approach or implement key retrieval
            
            logger.info(f"Created reCAPTCHA key for domain {domain}: {site_key}")
            
            # TODO: Implement secret key retrieval from Admin API
            # For now, return placeholder - in production, retrieve via separate API call
            secret_key = data.get("secretKey", "")  
            
            return (site_key, secret_key)
            
    except httpx.HTTPStatusError as e:
        logger.error(f"Failed to create reCAPTCHA key for {domain}: {e.response.status_code} - {e.response.text}")
        raise Exception(f"reCAPTCHA key creation failed: {e.response.status_code}")
    except Exception as e:
        logger.error(f"Error creating reCAPTCHA key for {domain}: {str(e)}")
        raise


async def store_recaptcha_keys(form_id: str, site_key: str, secret_key: str) -> None:
    """
    Store domain-specific reCAPTCHA keys in the database (secret is encrypted).
    
    Args:
        form_id: Form ID
        site_key: Public site key
        secret_key: Secret key (will be encrypted)
    """
    encrypted_secret = _encrypt_secret(secret_key)
    
    async with async_session_maker() as session:
        await session.execute(
            text("""
                UPDATE forms
                SET recaptcha_site_key = :site_key,
                    recaptcha_secret_key = :secret_key,
                    recaptcha_key_created_at = NOW(),
                    updated_at = NOW()
                WHERE id = :form_id
            """),
            {
                "form_id": form_id,
                "site_key": site_key,
                "secret_key": encrypted_secret
            }
        )
        await session.commit()
    
    logger.info(f"Stored reCAPTCHA keys for form {form_id}")


async def get_recaptcha_keys(form_id: str) -> Optional[Dict[str, str]]:
    """
    Retrieve domain-specific reCAPTCHA keys for a form.
    
    Args:
        form_id: Form ID
        
    Returns:
        Dict with 'site_key' and 'secret_key' (decrypted), or None if not found
    """
    async with async_session_maker() as session:
        result = await session.execute(
            text("""
                SELECT recaptcha_site_key, recaptcha_secret_key
                FROM forms
                WHERE id = :form_id
                LIMIT 1
            """),
            {"form_id": form_id}
        )
        row = result.mappings().first()
    
    if not row or not row.get("recaptcha_site_key"):
        return None
    
    try:
        decrypted_secret = _decrypt_secret(row["recaptcha_secret_key"])
        return {
            "site_key": row["recaptcha_site_key"],
            "secret_key": decrypted_secret
        }
    except Exception as e:
        logger.error(f"Failed to decrypt reCAPTCHA secret for form {form_id}: {e}")
        return None


async def provision_recaptcha_for_domain(form_id: str, domain: str) -> Dict[str, str]:
    """
    Complete workflow: Create and store reCAPTCHA keys for a custom domain.
    
    Args:
        form_id: Form ID
        domain: Custom domain
        
    Returns:
        Dict with 'site_key' and 'secret_key'
    """
    # Check if keys already exist
    existing_keys = await get_recaptcha_keys(form_id)
    if existing_keys:
        logger.info(f"reCAPTCHA keys already exist for form {form_id}")
        return existing_keys
    
    # Create new keys via Admin API
    site_key, secret_key = await create_recaptcha_key_for_domain(domain)
    
    # Store encrypted in database
    await store_recaptcha_keys(form_id, site_key, secret_key)
    
    return {
        "site_key": site_key,
        "secret_key": secret_key
    }


async def delete_recaptcha_keys(form_id: str) -> None:
    """
    Delete reCAPTCHA keys for a form (when custom domain is removed).
    
    Args:
        form_id: Form ID
    """
    async with async_session_maker() as session:
        await session.execute(
            text("""
                UPDATE forms
                SET recaptcha_site_key = NULL,
                    recaptcha_secret_key = NULL,
                    recaptcha_key_created_at = NULL,
                    updated_at = NOW()
                WHERE id = :form_id
            """),
            {"form_id": form_id}
        )
        await session.commit()
    
    logger.info(f"Deleted reCAPTCHA keys for form {form_id}")
