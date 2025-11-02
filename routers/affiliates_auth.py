"""
Affiliate authentication router - handles signup, login, password reset
Uses Neon PostgreSQL for storage with JWT tokens (not Firebase Auth)
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy import text
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

async def get_db_connection():
    """Get database connection from pool"""
    from db.database import get_session
    session = get_session()
    return await session.__anext__()

@router.post('/signup')
async def signup(request: SignupRequest):
    """Create new affiliate account"""
    session = None
    try:
        session = await get_db_connection()
        
        # Check if email already exists
        result = await session.execute(
            text('SELECT id FROM affiliates WHERE email = :email'),
            {'email': request.email.lower()}
        )
        existing = result.fetchone()
        if existing:
            raise HTTPException(status_code=400, detail='Email already registered')
        
        # Generate affiliate ID and code
        affiliate_id = secrets.token_urlsafe(16)
        affiliate_code = generate_affiliate_code(request.email)
        
        # Ensure affiliate code is unique
        while True:
            code_result = await session.execute(
                text('SELECT id FROM affiliates WHERE affiliate_code = :code'),
                {'code': affiliate_code}
            )
            if not code_result.fetchone():
                break
            affiliate_code = generate_affiliate_code(request.email + secrets.token_hex(2))
        
        # Hash password
        password_hash = hash_password(request.password)
        
        # Insert new affiliate
        await session.execute(
            text('''
            INSERT INTO affiliates (id, email, password_hash, name, affiliate_code, 
                                 created_at, updated_at)
            VALUES (:id, :email, :password_hash, :name, :affiliate_code, 
                   NOW(), NOW())
            '''),
            {
                'id': affiliate_id,
                'email': request.email.lower(),
                'password_hash': password_hash,
                'name': request.name,
                'affiliate_code': affiliate_code
            }
        )
        
        # Commit the transaction
        await session.commit()
        
        # Generate tokens
        access_token = generate_jwt(affiliate_id, request.email)
        refresh_token = generate_jwt(affiliate_id, request.email, is_refresh=True)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer',
            'affiliate_id': affiliate_id,
            'email': request.email,
            'name': request.name,
            'affiliate_code': affiliate_code,
            'redirect_to': '/affiliates/dashboard'  # Add redirect URL
        }
        
    except HTTPException:
        if session:
            await session.rollback()
        raise
    except Exception as e:
        print(f'Affiliate signup error: {str(e)}')
        if session:
            await session.rollback()
        raise HTTPException(status_code=500, detail='Error creating account')
    finally:
        if session:
            await session.close()

@router.post('/login')
async def login(request: LoginRequest):
    """Authenticate affiliate and return JWT tokens"""
    session = None
    try:
        session = await get_db_connection()
        
        # Find affiliate by email
        result = await session.execute(
            text('''
            SELECT id, email, name, password_hash, affiliate_code, 
                   is_active, email_verified
            FROM affiliates
            WHERE email = :email
            '''),
            {'email': request.email.lower()}
        )
        affiliate = result.mappings().first()  # Changed to use mappings() for proper dict access
        
        if not affiliate or not verify_password(request.password, affiliate['password_hash']):
            raise HTTPException(status_code=401, detail='Invalid email or password')
        
        # Generate new tokens
        access_token = generate_jwt(str(affiliate['id']), affiliate['email'])
        refresh_token = generate_jwt(str(affiliate['id']), affiliate['email'], is_refresh=True)
        
        # Ensure we have all required fields
        response_data = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer',
            'affiliate_id': str(affiliate['id']),  # Ensure ID is string
            'email': affiliate['email'],
            'name': affiliate['name'],
            'affiliate_code': affiliate.get('affiliate_code', ''),  # Use get with default
            'redirect_to': '/affiliates/dashboard'  # Add redirect URL
        }
        
        # Commit any pending transactions before returning
        await session.commit()
        return response_data
        
    except HTTPException:
        if session:
            await session.rollback()
        raise
    except Exception as e:
        print(f'Affiliate login error: {str(e)}')
        if session:
            await session.rollback()
        raise HTTPException(status_code=500, detail='Error during login')
    finally:
        if session:
            try:
                await session.close()
            except Exception as e:
                print(f'Error closing session: {str(e)}')

@router.post('/password-reset')
async def password_reset(request: PasswordResetRequest):
    """Send password reset email to affiliate"""
    session = None
    try:
        session = await get_db_connection()
        
        # Find affiliate by email
        result = await session.execute(
            text('SELECT id, email, name FROM affiliates WHERE email = :email'),
            {'email': request.email.lower()}
        )
        affiliate = result.fetchone()
        
        if not affiliate:
            # Don't reveal if email exists or not
            return {'detail': 'If an account exists with this email, a password reset link has been sent'}
        
        # Generate reset token (valid for 1 hour)
        reset_token = secrets.token_urlsafe(32)
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        
        # Store reset token in database
        await session.execute(
            text('''
            INSERT INTO password_reset_tokens (user_id, token, expires_at, is_used)
            VALUES (:user_id, :token, :expires_at, false)
            ON CONFLICT (user_id) 
            DO UPDATE SET token = :token, expires_at = :expires_at, is_used = false, created_at = NOW()
            '''),
            {
                'user_id': affiliate['id'],
                'token': reset_token,
                'expires_at': expires_at
            }
        )
        
        await session.commit()
        
        # In a real app, you would send an email here with the reset link
        # For now, we'll just log it
        reset_link = f"https://yourdomain.com/reset-password?token={reset_token}"
        print(f"Password reset link for {affiliate['email']}: {reset_link}")
        
        return {'detail': 'If an account exists with this email, a password reset link has been sent'}
        
    except Exception as e:
        if session:
            await session.rollback()
        print(f'Password reset error: {str(e)}')
        raise HTTPException(status_code=500, detail='Error processing password reset')
    finally:
        if session:
            await session.close()

@router.get('/verify-token')
async def verify_token(token: str):
    """Verify JWT token and return affiliate info"""
    session = None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        if payload.get('type') != 'access':
            raise HTTPException(status_code=401, detail='Invalid token type')
        
        session = await get_db_connection()
        result = await session.execute(
            text('''
            SELECT id, email, name, affiliate_code, email_verified, is_active
            FROM affiliates
            WHERE id = :affiliate_id
            '''),
            {'affiliate_id': payload['affiliate_id']}
        )
        affiliate = result.fetchone()
        
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
    session = None
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        if payload.get('type') != 'refresh':
            raise HTTPException(status_code=401, detail='Invalid token type')
        
        session = await get_db_connection()
        
        # Verify the affiliate exists and is active
        result = await session.execute(
            text('''
            SELECT id, email, is_active
            FROM affiliates
            WHERE id = :affiliate_id
            '''),
            {'affiliate_id': payload['affiliate_id']}
        )
        affiliate = result.fetchone()
        
        if not affiliate or not affiliate['is_active']:
            raise HTTPException(status_code=401, detail='Invalid or inactive account')
        
        # Generate new access token
        new_access_token = generate_jwt(affiliate['id'], affiliate['email'])
        
        return {
            'access_token': new_access_token,
            'token_type': 'bearer'
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Refresh token expired')
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail='Invalid refresh token')
    except Exception as e:
        print(f'Token refresh error: {e}')
        raise HTTPException(status_code=500, detail='Error refreshing token')
    finally:
        if session:
            await session.close()
