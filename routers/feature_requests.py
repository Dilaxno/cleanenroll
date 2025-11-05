"""
Feature request endpoint to send user feature requests to founder email.
"""
from fastapi import APIRouter, Depends, File, Form, UploadFile, HTTPException, Request
from typing import List, Optional
import os
from datetime import datetime
import base64
import logging

try:
    from ..utils.email import send_email_html  # type: ignore
    from ..utils.firebase_admin_adapter import admin_auth  # type: ignore
except Exception:
    from utils.email import send_email_html  # type: ignore
    from utils.firebase_admin_adapter import admin_auth  # type: ignore

logger = logging.getLogger(__name__)

router = APIRouter()

FOUNDER_EMAIL = "eric@cleanenroll.com"

def _verify_firebase_token(request: Request) -> Optional[str]:
    """Verify Firebase ID token from Authorization header. Returns uid or None."""
    try:
        authz = request.headers.get("authorization") or request.headers.get("Authorization")
        if not authz or not authz.lower().startswith("bearer "):
            return None
        token = authz.split(" ", 1)[1].strip()
        if not token:
            return None
        decoded = admin_auth.verify_id_token(token)
        return decoded.get("uid")
    except Exception as e:
        logger.error(f"Failed to verify Firebase token: {e}")
        return None

@router.post("/feature-request")
async def submit_feature_request(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    useCase: Optional[str] = Form(""),
    priority: str = Form("nice-to-have"),
    userEmail: str = Form(...),
    userName: str = Form("User"),
    images: List[UploadFile] = File(default=[])
):
    """
    Submit a feature request and send it to the founder's email.
    """
    # Verify authentication
    uid = _verify_firebase_token(request)
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    try:
        # Build email content
        priority_colors = {
            'nice-to-have': '#3B82F6',
            'important': '#F59E0B',
            'critical': '#EF4444'
        }
        priority_labels = {
            'nice-to-have': 'Nice to Have',
            'important': 'Important',
            'critical': 'Critical'
        }
        
        priority_color = priority_colors.get(priority, '#3B82F6')
        priority_label = priority_labels.get(priority, priority)
        
        # Read and encode images
        image_attachments = []
        image_html = ""
        for idx, image in enumerate(images):
            if image.filename:
                content = await image.read()
                # Add as attachment
                image_attachments.append({
                    'filename': image.filename,
                    'content': base64.b64encode(content).decode(),
                    'content_type': image.content_type or 'image/png'
                })
                # Add to HTML (inline)
                encoded = base64.b64encode(content).decode()
                image_html += f'''
                <div style="margin: 10px 0;">
                    <img src="data:{image.content_type};base64,{encoded}" style="max-width: 600px; height: auto; border-radius: 8px; border: 1px solid #e5e7eb;" />
                    <p style="margin: 5px 0; font-size: 12px; color: #6b7280;">{image.filename}</p>
                </div>
                '''
        
        html_content = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f9fafb;">
            <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
                <!-- Header -->
                <div style="text-align: center; margin-bottom: 30px;">
                    <div style="background: linear-gradient(135deg, #A855F7 0%, #7C3AED 100%); padding: 20px; border-radius: 12px;">
                        <h1 style="margin: 0; color: white; font-size: 24px; font-weight: bold;">💡 New Feature Request</h1>
                    </div>
                </div>
                
                <!-- Main Content -->
                <div style="background: white; border-radius: 12px; padding: 30px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                    <!-- User Info -->
                    <div style="background: #f3f4f6; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                        <p style="margin: 5px 0; color: #374151; font-size: 14px;"><strong>From:</strong> {userName}</p>
                        <p style="margin: 5px 0; color: #374151; font-size: 14px;"><strong>Email:</strong> {userEmail}</p>
                        <p style="margin: 5px 0; color: #374151; font-size: 14px;"><strong>Date:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
                    </div>
                    
                    <!-- Priority Badge -->
                    <div style="margin-bottom: 20px;">
                        <span style="display: inline-block; padding: 6px 12px; background-color: {priority_color}; color: white; border-radius: 6px; font-size: 12px; font-weight: 600;">
                            {priority_label}
                        </span>
                    </div>
                    
                    <!-- Title -->
                    <div style="margin-bottom: 20px;">
                        <h2 style="margin: 0 0 10px 0; color: #111827; font-size: 20px; font-weight: 700;">{title}</h2>
                    </div>
                    
                    <!-- Description -->
                    <div style="margin-bottom: 20px;">
                        <h3 style="margin: 0 0 10px 0; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600;">Description</h3>
                        <p style="margin: 0; color: #374151; font-size: 15px; line-height: 1.6; white-space: pre-wrap;">{description}</p>
                    </div>
                    
                    {f'''
                    <!-- Use Case -->
                    <div style="margin-bottom: 20px;">
                        <h3 style="margin: 0 0 10px 0; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600;">Use Case</h3>
                        <p style="margin: 0; color: #374151; font-size: 15px; line-height: 1.6; white-space: pre-wrap;">{useCase}</p>
                    </div>
                    ''' if useCase else ''}
                    
                    {f'''
                    <!-- Screenshots -->
                    <div style="margin-bottom: 20px;">
                        <h3 style="margin: 0 0 10px 0; color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600;">Screenshots / Mockups</h3>
                        {image_html}
                    </div>
                    ''' if image_html else ''}
                </div>
                
                <!-- Footer -->
                <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0; color: #9ca3af; font-size: 13px;">
                        This feature request was submitted through CleanEnroll Dashboard
                    </p>
                </div>
            </div>
        </body>
        </html>
        '''
        
        # Send email
        subject = f"[Feature Request] {title}"
        
        send_email_html(
            to_email=FOUNDER_EMAIL,
            subject=subject,
            html_body=html_content
        )
        
        return {"success": True, "message": "Feature request submitted successfully"}
        
    except Exception as e:
        print(f"Error submitting feature request: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit feature request")
