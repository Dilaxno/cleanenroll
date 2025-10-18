"""
AES-256 encryption/decryption utilities for submission data
Uses cryptography library's low-level hazmat API for AES-256-GCM
"""
import os
import base64
import json
from typing import Any, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger("backend.encryption")

def _get_encryption_key() -> bytes:
    """
    Get the AES-256 encryption key from environment variable.
    Key should be 32 bytes (256 bits) base64-encoded.
    """
    key_b64 = os.getenv("SUBMISSION_ENCRYPTION_KEY", "")
    if not key_b64:
        raise ValueError("SUBMISSION_ENCRYPTION_KEY environment variable not set")
    
    try:
        key = base64.b64decode(key_b64)
        if len(key) != 32:
            raise ValueError("Encryption key must be 32 bytes (256 bits)")
        return key
    except Exception as e:
        raise ValueError(f"Invalid encryption key format: {e}")

def encrypt_submission_data(data: Any) -> str:
    """
    Encrypt submission data using AES-256-GCM.
    
    Args:
        data: The data to encrypt (dict, list, string, etc.)
        
    Returns:
        Base64-encoded string containing IV + ciphertext + auth tag
        Format: base64(iv || ciphertext || tag)
    """
    try:
        # Convert data to JSON string
        if isinstance(data, (dict, list)):
            plaintext = json.dumps(data)
        else:
            plaintext = str(data)
        
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Get encryption key
        key = _get_encryption_key()
        
        # Generate random 12-byte IV (96 bits, recommended for GCM)
        iv = os.urandom(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
        
        # Get the authentication tag
        tag = encryptor.tag
        
        # Combine IV + ciphertext + tag
        encrypted = iv + ciphertext + tag
        
        # Return base64-encoded
        return base64.b64encode(encrypted).decode('utf-8')
        
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise

def decrypt_submission_data(encrypted_data: str, return_json: bool = True) -> Any:
    """
    Decrypt submission data encrypted with AES-256-GCM.
    
    Args:
        encrypted_data: Base64-encoded encrypted data
        return_json: If True, parse as JSON; if False, return raw string
        
    Returns:
        Decrypted data (parsed JSON or raw string)
    """
    try:
        # Decode from base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract components
        iv = encrypted_bytes[:12]  # First 12 bytes
        tag = encrypted_bytes[-16:]  # Last 16 bytes (GCM tag)
        ciphertext = encrypted_bytes[12:-16]  # Everything in between
        
        # Get encryption key
        key = _get_encryption_key()
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = plaintext_bytes.decode('utf-8')
        
        # Parse JSON if requested
        if return_json:
            try:
                return json.loads(plaintext)
            except json.JSONDecodeError:
                # If it's not valid JSON, return as string
                return plaintext
        else:
            return plaintext
            
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise

def generate_encryption_key() -> str:
    """
    Generate a new random 32-byte (256-bit) encryption key.
    Returns base64-encoded key suitable for environment variable.
    
    Usage:
        python -c "from utils.encryption import generate_encryption_key; print(generate_encryption_key())"
    """
    key = os.urandom(32)
    return base64.b64encode(key).decode('utf-8')
