"""
Developer Waitlist Router
Handles developer portal waitlist signups and admin retrieval
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
import firebase_admin.auth
from db.database import get_db_connection
import logging

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

async def get_current_user_uid(authorization: str = Depends(lambda: None)) -> str:
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
    """Check if user is an admin"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT is_admin FROM users WHERE uid = %s",
                (uid,)
            )
            result = cur.fetchone()
            return result and result[0] is True
    finally:
        conn.close()


# ============================================================================
# Public Endpoints
# ============================================================================

@router.post("/submit", status_code=status.HTTP_201_CREATED)
async def submit_waitlist(data: DeveloperWaitlistSubmit):
    """
    Public endpoint to submit developer waitlist signup
    No authentication required
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Check if email already exists
            cur.execute(
                "SELECT id FROM developer_waitlist WHERE email = %s",
                (data.email,)
            )
            existing = cur.fetchone()
            
            if existing:
                # Update existing entry
                cur.execute(
                    """
                    UPDATE developer_waitlist
                    SET name = %s, company = %s, role = %s, interests = %s,
                        use_cases = %s, additional_info = %s, updated_at = NOW()
                    WHERE email = %s
                    RETURNING id
                    """,
                    (
                        data.name,
                        data.company,
                        data.role,
                        data.interests,
                        data.use_cases,
                        data.additional_info,
                        data.email
                    )
                )
            else:
                # Insert new entry
                cur.execute(
                    """
                    INSERT INTO developer_waitlist
                    (email, name, company, role, interests, use_cases, additional_info)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        data.email,
                        data.name,
                        data.company,
                        data.role,
                        data.interests,
                        data.use_cases,
                        data.additional_info
                    )
                )
            
            result = cur.fetchone()
            conn.commit()
            
            logger.info(f"Developer waitlist signup: {data.email}")
            
            return {
                "success": True,
                "message": "Successfully joined the waitlist!",
                "id": result[0]
            }
            
    except Exception as e:
        conn.rollback()
        logger.error(f"Error submitting waitlist: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit waitlist signup"
        )
    finally:
        conn.close()


# ============================================================================
# Admin-Only Endpoints
# ============================================================================

@router.get("/list", response_model=List[DeveloperWaitlistResponse])
async def list_waitlist(authorization: str = Depends(lambda req: req.headers.get("authorization"))):
    """
    Admin-only endpoint to retrieve all developer waitlist signups
    Requires authentication and admin privileges
    """
    # Verify authentication
    uid = await get_current_user_uid(authorization)
    
    # Verify admin status
    is_admin = await verify_admin(uid)
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, name, company, role, interests, use_cases, 
                       additional_info, created_at
                FROM developer_waitlist
                ORDER BY created_at DESC
                """
            )
            rows = cur.fetchall()
            
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
    finally:
        conn.close()


@router.get("/stats")
async def get_waitlist_stats(authorization: str = Depends(lambda req: req.headers.get("authorization"))):
    """
    Admin-only endpoint to get waitlist statistics
    """
    # Verify authentication
    uid = await get_current_user_uid(authorization)
    
    # Verify admin status
    is_admin = await verify_admin(uid)
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Get total count
            cur.execute("SELECT COUNT(*) FROM developer_waitlist")
            total = cur.fetchone()[0]
            
            # Get count from last 7 days
            cur.execute(
                """
                SELECT COUNT(*) FROM developer_waitlist
                WHERE created_at >= NOW() - INTERVAL '7 days'
                """
            )
            last_7_days = cur.fetchone()[0]
            
            # Get count from last 30 days
            cur.execute(
                """
                SELECT COUNT(*) FROM developer_waitlist
                WHERE created_at >= NOW() - INTERVAL '30 days'
                """
            )
            last_30_days = cur.fetchone()[0]
            
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
    finally:
        conn.close()
