"""
Coming Soon Waitlist Router
Handles email signups for the coming soon page
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
from db.database import async_session_maker
from sqlalchemy import text
import logging
from utils.email import render_email, send_email_html

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/waitlist", tags=["waitlist"])


# ============================================================================
# Request/Response Models
# ============================================================================

class WaitlistSubmit(BaseModel):
    email: EmailStr
    use_case: str = None
    leads_per_month: str = None


class WaitlistResponse(BaseModel):
    success: bool
    message: str
    id: int = None


# ============================================================================
# Public Endpoints
# ============================================================================

@router.post("", status_code=status.HTTP_201_CREATED, response_model=WaitlistResponse)
async def submit_waitlist(data: WaitlistSubmit):
    """
    Public endpoint to submit coming soon waitlist signup
    No authentication required
    """
    async with async_session_maker() as session:
        try:
            # Check if email already exists
            result = await session.execute(
                text("SELECT id FROM coming_soon_waitlist WHERE email = :email"),
                {"email": data.email}
            )
            existing = result.fetchone()
            
            if existing:
                # Update use_case and leads_per_month if provided
                if data.use_case or data.leads_per_month:
                    await session.execute(
                        text("UPDATE coming_soon_waitlist SET use_case = COALESCE(:use_case, use_case), leads_per_month = COALESCE(:leads_per_month, leads_per_month) WHERE id = :id"),
                        {"use_case": data.use_case, "leads_per_month": data.leads_per_month, "id": existing[0]}
                    )
                    await session.commit()
                return WaitlistResponse(
                    success=True,
                    message="You're already on the waitlist!",
                    id=existing[0]
                )
            
            # Insert new entry
            result = await session.execute(
                text("""
                    INSERT INTO coming_soon_waitlist (email, use_case, leads_per_month)
                    VALUES (:email, :use_case, :leads_per_month)
                    RETURNING id
                """),
                {"email": data.email, "use_case": data.use_case, "leads_per_month": data.leads_per_month}
            )
            
            row = result.fetchone()
            await session.commit()
            
            logger.info(f"Coming soon waitlist signup: {data.email}")
            
            # Send welcome email
            try:
                email_html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                </head>
                <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <img src="https://cleanenroll.com/LogoCleanEnroll%20Light.svg" alt="CleanEnroll" style="height: 50px; width: auto;">
                    </div>
                    
                    <h1 style="color: #3D6B2F; font-size: 24px; margin-bottom: 20px;">You're on the list! 🎉</h1>
                    
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        Thanks for joining the CleanEnroll waitlist! We're excited to have you on board.
                    </p>
                    
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        We're building something special — a form builder that helps you collect quality leads by filtering out spam and validating every submission.
                    </p>
                    
                    <p style="font-size: 16px; margin-bottom: 20px;">
                        You'll be among the first to know when we launch. Stay tuned!
                    </p>
                    
                    <div style="background: #F2F7F0; border-radius: 8px; padding: 20px; margin: 30px 0;">
                        <h3 style="color: #3D6B2F; margin-top: 0;">What to expect:</h3>
                        <ul style="margin: 0; padding-left: 20px;">
                            <li>Early access to CleanEnroll</li>
                            <li>Exclusive launch discounts</li>
                            <li>Updates on new features</li>
                        </ul>
                    </div>
                    
                    <p style="font-size: 14px; color: #666; margin-top: 30px;">
                        Questions? Reply to this email — we'd love to hear from you!
                    </p>
                    
                    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                    
                    <p style="font-size: 12px; color: #999; text-align: center;">
                        © 2025 CleanEnroll. All rights reserved.<br>
                        You're receiving this because you signed up for our waitlist.
                    </p>
                </body>
                </html>
                """
                send_email_html(
                    to_email=data.email,
                    subject="You're on the CleanEnroll waitlist! 🎉",
                    html_body=email_html
                )
                logger.info(f"Welcome email sent to {data.email}")
            except Exception as email_error:
                # Log error but don't fail the signup
                logger.error(f"Failed to send welcome email to {data.email}: {email_error}")
            
            # Send notification to team
            try:
                use_case_display = data.use_case.replace('_', ' ').title() if data.use_case else 'Not specified'
                leads_display = data.leads_per_month if data.leads_per_month else 'Not specified'
                notification_html = f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #3D6B2F;">New Coming Soon Waitlist Signup</h2>
                    <p>A new user has joined the coming soon waitlist:</p>
                    <div style="background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin: 16px 0;">
                        <p><strong>Email:</strong> {data.email}</p>
                        <p><strong>Use Case:</strong> {use_case_display}</p>
                        <p><strong>Leads/Month:</strong> {leads_display}</p>
                    </div>
                </div>
                """
                send_email_html(
                    to_email="eric@cleanenroll.com",
                    subject=f"New Waitlist Signup: {data.email}",
                    html_body=notification_html
                )
            except Exception as notification_error:
                logger.error(f"Failed to send notification email: {notification_error}")
            
            return WaitlistResponse(
                success=True,
                message="Successfully joined the waitlist!",
                id=row[0]
            )
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Error submitting waitlist: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to submit waitlist signup"
            )


@router.get("/count")
async def get_waitlist_count():
    """
    Public endpoint to get the current waitlist count
    """
    async with async_session_maker() as session:
        try:
            result = await session.execute(
                text("SELECT COUNT(*) FROM coming_soon_waitlist")
            )
            count = result.scalar() or 0
            
            # Add a base number to make it look more established
            display_count = count + 500
            
            return {"count": display_count}
            
        except Exception as e:
            logger.error(f"Error getting waitlist count: {e}")
            # Return a default count on error
            return {"count": 500}
