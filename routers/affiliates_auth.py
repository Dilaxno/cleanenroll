"""
Affiliate authentication router - handles signup, login, password reset
Uses Neon PostgreSQL for storage with JWT tokens (not Firebase Auth)
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
import secrets
import hashlib
import jwt
import datetime
from typing import Optional
import os

router = APIRouter()

# JWT configuration
JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24
REFRESH_TOKEN_DAYS = 30

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    name: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == password_hash

def generate_jwt(affiliate_id: str, email: str, is_refresh: bool = False) -> str:
    """Generate JWT token for affiliate"""
    exp_hours = REFRESH_TOKEN_DAYS * 24 if is_refresh else JWT_EXPIRATION_HOURS
    payload = {
        'affiliate_id': affiliate_id,
        'email': email,
        'type': 'refresh' if is_refresh else 'access',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=exp_hours)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def generate_affiliate_code(email: str) -> str:
    """Generate unique affiliate code from email"""
    base = email.split('@')[0].upper()
    random_suffix = secrets.token_hex(3).upper()
    return f"{base[:6]}{random_suffix}"

def get_db_connection():
    """Get database connection from pool"""
    from db.database import get_connection
    return get_connection()

@router.post('/signup')
async def signup(request: SignupRequest):
    """Create new affiliate account"""
    try:
        pool = get_db_connection()
        
        async with pool.acquire() as conn:
            # Check if email already exists
            existing = await conn.fetchrow(
                'SELECT id FROM affiliates WHERE email = $1',
                request.email.lower()
            )
            if existing:
                raise HTTPException(status_code=400, detail='Email already registered')
            
            # Generate affiliate ID and code
            affiliate_id = secrets.token_urlsafe(16)
            affiliate_code = generate_affiliate_code(request.email)
            
            # Ensure affiliate code is unique
            code_exists = await conn.fetchrow(
                'SELECT id FROM affiliates WHERE affiliate_code = $1',
                affiliate_code
            )
            while code_exists:
                affiliate_code = generate_affiliate_code(request.email + secrets.token_hex(2))
                code_exists = await conn.fetchrow(
                    'SELECT id FROM affiliates WHERE affiliate_code = $1',
                    affiliate_code
                )
            
            # Hash password
            password_hash = hash_password(request.password)
            
            # Insert new affiliate
            await conn.execute(
                '''
                INSERT INTO affiliates (
                    id, email, name, password_hash, affiliate_code,
                    email_verified, is_active, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
                ''',
                affiliate_id,
                request.email.lower(),
                request.name,
                password_hash,
                affiliate_code,
                False,  # email_verified
                True    # is_active
            )
            
            # Generate tokens
            access_token = generate_jwt(affiliate_id, request.email)
            refresh_token = generate_jwt(affiliate_id, request.email, is_refresh=True)
            
            return {
                'success': True,
                'token': access_token,
                'refreshToken': refresh_token,
                'affiliate': {
                    'id': affiliate_id,
                    'email': request.email,
                    'name': request.name,
                    'affiliate_code': affiliate_code
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        print(f'Affiliate signup error: {e}')
        raise HTTPException(status_code=500, detail='Failed to create account')

@router.post('/login')
async def login(request: LoginRequest):
    """Authenticate affiliate and return JWT tokens"""
    try:
        pool = get_db_connection()
        
        async with pool.acquire() as conn:
            # Find affiliate by email
            affiliate = await conn.fetchrow(
                '''
                SELECT id, email, name, password_hash, affiliate_code, 
                       is_active, email_verified
                FROM affiliates
                WHERE email = $1
                ''',
                request.email.lower()
            )
            
            if not affiliate:
                raise HTTPException(status_code=401, detail='Invalid credentials')
            
            # Verify password
            if not verify_password(request.password, affiliate['password_hash']):
                raise HTTPException(status_code=401, detail='Invalid credentials')
            
            # Check if account is active
            if not affiliate['is_active']:
                raise HTTPException(status_code=403, detail='Account is disabled')
            
            # Update last login
            await conn.execute(
                'UPDATE affiliates SET last_login_at = NOW() WHERE id = $1',
                affiliate['id']
            )
            
            # Generate tokens
            access_token = generate_jwt(affiliate['id'], affiliate['email'])
            refresh_token = generate_jwt(affiliate['id'], affiliate['email'], is_refresh=True)
            
            return {
                'success': True,
                'token': access_token,
                'refreshToken': refresh_token,
                'affiliate': {
                    'id': affiliate['id'],
                    'email': affiliate['email'],
                    'name': affiliate['name'],
                    'affiliate_code': affiliate['affiliate_code'],
                    'email_verified': affiliate['email_verified']
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        print(f'Affiliate login error: {e}')
        raise HTTPException(status_code=500, detail='Failed to authenticate')

@router.post('/password-reset')
async def password_reset(request: PasswordResetRequest):
    """Send password reset email to affiliate"""
    try:
        pool = get_db_connection()
        
        async with pool.acquire() as conn:
            # Find affiliate by email
            affiliate = await conn.fetchrow(
                'SELECT id, email, name FROM affiliates WHERE email = $1',
                request.email.lower()
            )
            
            if not affiliate:
                # Don't reveal if email exists or not
                return {
                    'success': True,
                    'message': 'If the email exists, a reset link has been sent'
                }
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            token_id = secrets.token_urlsafe(16)
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            
            # Store reset token
            await conn.execute(
                '''
                INSERT INTO affiliate_reset_tokens (
                    id, affiliate_id, token, expires_at, used
                )
                VALUES ($1, $2, $3, $4, $5)
                ''',
                token_id,
                affiliate['id'],
                reset_token,
                expires_at,
                False
            )
            
            # TODO: Send email with reset link
            # Reset link would be: https://yourapp.com/affiliates/reset-password?token={reset_token}
            print(f"Password reset token for {affiliate['email']}: {reset_token}")
            
            return {
                'success': True,
                'message': 'Password reset email sent'
            }
    except Exception as e:
        print(f'Password reset error: {e}')
        raise HTTPException(status_code=500, detail='Failed to send reset email')

@router.post('/verify-token')
async def verify_token(token: str):
    """Verify JWT token and return affiliate info"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        if payload.get('type') != 'access':
            raise HTTPException(status_code=401, detail='Invalid token type')
        
        pool = get_db_connection()
        async with pool.acquire() as conn:
            affiliate = await conn.fetchrow(
                '''
                SELECT id, email, name, affiliate_code, email_verified, is_active
                FROM affiliates
                WHERE id = $1
                ''',
                payload['affiliate_id']
            )
            
            if not affiliate or not affiliate['is_active']:
                raise HTTPException(status_code=401, detail='Invalid or inactive account')
            
            return {
                'success': True,
                'affiliate': {
                    'id': affiliate['id'],
                    'email': affiliate['email'],
                    'name': affiliate['name'],
                    'affiliate_code': affiliate['affiliate_code'],
                    'email_verified': affiliate['email_verified']
                }
            }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Token expired')
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail='Invalid token')
    except Exception as e:
        print(f'Token verification error: {e}')
        raise HTTPException(status_code=401, detail='Token verification failed')

@router.post('/refresh')
async def refresh_token(refresh_token: str):
    """Refresh access token using refresh token"""
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        if payload.get('type') != 'refresh':
            raise HTTPException(status_code=401, detail='Invalid token type')
        
        # Generate new access token
        new_access_token = generate_jwt(payload['affiliate_id'], payload['email'])
        
        return {
            'success': True,
            'token': new_access_token
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Refresh token expired')
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail='Invalid refresh token')
    except Exception as e:
        print(f'Token refresh error: {e}')
        raise HTTPException(status_code=401, detail='Failed to refresh token')
