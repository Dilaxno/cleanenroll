"""
Developer Waitlist Router
Handles developer portal waitlist signups and admin retrieval
"""

from fastapi import APIRouter, Depends, HTTPException, status, Header
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
import firebase_admin.auth
from db.database import async_session_maker
from sqlalchemy import text
import logging
import os
from utils.email import render_email, send_email_html

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/developer-waitlist", tags=["developer-waitlist"])


# ============================================================================
# Request/Response Models
# ============================================================================

class DeveloperWaitlistSubmit(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    company: Optional[str] = None
    role: Optional[str] = None
    interests: List[str] = Field(default_factory=list)
    use_cases: Optional[str] = None
    additional_info: Optional[str] = None


class DeveloperWaitlistResponse(BaseModel):
    id: int
    email: str
    name: Optional[str]
    company: Optional[str]
    role: Optional[str]
    interests: List[str]
    use_cases: Optional[str]
    additional_info: Optional[str]
    created_at: str


# ============================================================================
# Authentication Helper
# ============================================================================

async def get_current_user_uid(authorization: str = Header(None)) -> str:
    """Extract and verify Firebase token from Authorization header"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header"
        )
    
    token = authorization.split("Bearer ")[1]
    try:
        decoded_token = firebase_admin.auth.verify_id_token(token)
        return decoded_token["uid"]
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )


async def verify_admin(uid: str) -> bool:
    """Check if user is an admin via email allowlist"""
    try:
        # Get user's email from Firebase token
        user = firebase_admin.auth.get_user(uid)
        email = str(user.email or "").lower()
        
        # Check against ALLOW_ADMIN_EMAILS environment variable
        allowlist = os.getenv("ALLOW_ADMIN_EMAILS", "")
        allowed_emails = {e.strip().lower() for e in allowlist.split(",") if e.strip()}
        
        return email in allowed_emails if email else False
    except Exception as e:
        logger.error(f"Error verifying admin: {e}")
        return False


# ============================================================================
# Public Endpoints
# ============================================================================

@router.post("/submit", status_code=status.HTTP_201_CREATED)
async def submit_waitlist(data: DeveloperWaitlistSubmit):
    """
    Public endpoint to submit developer waitlist signup
    No authentication required
    """
    async with async_session_maker() as session:
        try:
            # Check if email already exists
            result = await session.execute(
                text("SELECT id FROM developer_waitlist WHERE email = :email"),
                {"email": data.email}
            )
            existing = result.fetchone()
            
            if existing:
                # Update existing entry
                result = await session.execute(
                    text("""
                        UPDATE developer_waitlist
                        SET name = :name, company = :company, role = :role, interests = :interests,
                            use_cases = :use_cases, additional_info = :additional_info, updated_at = NOW()
                        WHERE email = :email
                        RETURNING id
                    """),
                    {
                        "name": data.name,
                        "company": data.company,
                        "role": data.role,
                        "interests": data.interests,
                        "use_cases": data.use_cases,
                        "additional_info": data.additional_info,
                        "email": data.email
                    }
                )
            else:
                # Insert new entry
                result = await session.execute(
                    text("""
                        INSERT INTO developer_waitlist
                        (email, name, company, role, interests, use_cases, additional_info)
                        VALUES (:email, :name, :company, :role, :interests, :use_cases, :additional_info)
                        RETURNING id
                    """),
                    {
                        "email": data.email,
                        "name": data.name,
                        "company": data.company,
                        "role": data.role,
                        "interests": data.interests,
                        "use_cases": data.use_cases,
                        "additional_info": data.additional_info
                    }
                )
            
            row = result.fetchone()
            await session.commit()
            
            logger.info(f"Developer waitlist signup: {data.email}")
            
            # Send welcome email to developer
            try:
                email_html = render_email(
                    "developer_waitlist_welcome.html",
                    {
                        "developer_name": data.name or "Developer",
                    }
                )
                send_email_html(
                    to_email=data.email,
                    subject="Welcome to the CleanEnroll Developer Portal Waitlist!",
                    html_body=email_html
                )
                logger.info(f"Welcome email sent to {data.email}")
            except Exception as email_error:
                # Log error but don't fail the signup
                logger.error(f"Failed to send welcome email to {data.email}: {email_error}")
            
            return {
                "success": True,
                "message": "Successfully joined the waitlist!",
                "id": row[0]
            }
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Error submitting waitlist: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to submit waitlist signup"
            )


# ============================================================================
# Admin-Only Endpoints
# ============================================================================

@router.get("/list", response_model=List[DeveloperWaitlistResponse])
async def list_waitlist(uid: str = Depends(get_current_user_uid)):
    """
    Admin-only endpoint to retrieve all developer waitlist signups
    Requires authentication and admin privileges
    """
    # uid is already verified from dependency
    
    # Verify admin status
    is_admin = await verify_admin(uid)
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    async with async_session_maker() as session:
        try:
            result = await session.execute(
                text("""
                    SELECT id, email, name, company, role, interests, use_cases, 
                           additional_info, created_at
                    FROM developer_waitlist
                    ORDER BY created_at DESC
                """)
            )
            rows = result.fetchall()
            
            waitlist_entries = []
            for row in rows:
                waitlist_entries.append({
                    "id": row[0],
                    "email": row[1],
                    "name": row[2],
                    "company": row[3],
                    "role": row[4],
                    "interests": row[5] or [],
                    "use_cases": row[6],
                    "additional_info": row[7],
                    "created_at": row[8].isoformat() if row[8] else None
                })
            
            return waitlist_entries
            
        except Exception as e:
            logger.error(f"Error retrieving waitlist: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve waitlist data"
            )


@router.get("/stats")
async def get_waitlist_stats(uid: str = Depends(get_current_user_uid)):
    """
    Admin-only endpoint to get waitlist statistics
    """
    # uid is already verified from dependency
    
    # Verify admin status
    is_admin = await verify_admin(uid)
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    async with async_session_maker() as session:
        try:
            # Get total count
            result = await session.execute(text("SELECT COUNT(*) FROM developer_waitlist"))
            total = result.scalar()
            
            # Get count from last 7 days
            result = await session.execute(
                text("""
                    SELECT COUNT(*) FROM developer_waitlist
                    WHERE created_at >= NOW() - INTERVAL '7 days'
                """)
            )
            last_7_days = result.scalar()
            
            # Get count from last 30 days
            result = await session.execute(
                text("""
                    SELECT COUNT(*) FROM developer_waitlist
                    WHERE created_at >= NOW() - INTERVAL '30 days'
                """)
            )
            last_30_days = result.scalar()
            
            return {
                "total": total,
                "last_7_days": last_7_days,
                "last_30_days": last_30_days
            }
            
        except Exception as e:
            logger.error(f"Error retrieving waitlist stats: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve waitlist statistics"
            )
