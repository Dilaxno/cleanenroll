from fastapi import APIRouter, HTTPException, Request
from typing import Dict, Any, Optional
import logging
from sqlalchemy import text
from db.database import async_session_maker
from utils.email import send_email_html, render_email
from email_validator import validate_email as _validate_email

router = APIRouter()
logger = logging.getLogger(__name__)

# Import rate limiter from main app
try:
    from main import limiter
except ImportError:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    limiter = Limiter(key_func=get_remote_address)


def _send_email_via_integration(owner_id: str, to_email: str, subject: str, html: str) -> bool:
    """Try to send email via user's configured email integration (Google, Microsoft, SMTP)."""
    try:
        # Import email integration utilities
        from routers.core import get_user_smtp_settings
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from cryptography.fernet import Fernet
        import base64
        import os
        
        # Try to get SMTP settings for this user
        smtp_settings = get_user_smtp_settings(owner_id)
        if not smtp_settings:
            return False
        
        # Decrypt password
        encryption_key = os.getenv("ENCRYPTION_KEY", "").strip()
        if not encryption_key:
            return False
        
        fernet = Fernet(encryption_key.encode())
        encrypted_password = smtp_settings.get("password", "")
        password = fernet.decrypt(encrypted_password.encode()).decode()
        
        # Send via SMTP
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp_settings.get("from_email")
        msg["To"] = to_email
        
        part = MIMEText(html, "html")
        msg.attach(part)
        
        with smtplib.SMTP(smtp_settings.get("host"), smtp_settings.get("port")) as server:
            server.starttls()
            server.login(smtp_settings.get("username"), password)
            server.send_message(msg)
        
        logger.info("Sent auto-reply via user SMTP integration owner=%s to=%s", owner_id, to_email)
        return True
    except Exception as e:
        logger.debug("Email integration send failed owner=%s: %s", owner_id, str(e))
        return False


async def send_auto_reply_email(
    form_data: Dict[str, Any],
    submission_payload: Dict[str, Any],
    owner_id: Optional[str] = None
) -> bool:
    """
    Send auto-reply thank you email to form submitter after submission.
    
    Args:
        form_data: Form configuration from database
        submission_payload: The submission data with field values
        owner_id: Owner user ID for email integration lookup
        
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        cfg = form_data or {}
        
        # Check if auto-reply is enabled
        if not bool(cfg.get("autoReplyEnabled")):
            logger.debug("Auto-reply not enabled for form")
            return False
        
        # Get the email field ID where recipient email is stored
        target_field_id = (cfg.get("autoReplyEmailFieldId") or "").strip()
        if not target_field_id or not isinstance(submission_payload, dict):
            logger.debug("No email field configured for auto-reply")
            return False
        
        # Extract recipient email from submission
        to_val = submission_payload.get(target_field_id)
        if isinstance(to_val, list) and to_val:
            to_email = str(to_val[0] or "").strip()
        else:
            to_email = str(to_val or "").strip()
        
        # Validate email format
        try:
            if to_email:
                _validate_email(to_email, check_deliverability=False)
            else:
                return False
        except Exception:
            logger.warning("Invalid email address for auto-reply: %s", to_email)
            return False
        
        # Get subject and body templates
        subject_tpl = (cfg.get("autoReplySubject") or "Thank you for your submission").strip()
        body_tpl = (cfg.get("autoReplyMessageHtml") or "").strip()
        
        # Derive name fields for personalization
        first_name = ""
        full_name = ""
        try:
            fields_def = cfg.get("fields") or []
            name_field = next(
                (f for f in fields_def if (
                    str(f.get("type")) == "full-name" or 
                    "name" in str(f.get("label", "")).lower()
                )), 
                None
            )
            if name_field:
                full_name = str(submission_payload.get(name_field.get("id")) or "").strip()
                if full_name:
                    parts = full_name.split()
                    first_name = parts[0] if parts else ""
        except Exception:
            pass
        
        # Token replacement for personalization
        tokens = {
            "@first_name": first_name,
            "@full_name": full_name,
            "@email": to_email,
            "@form_title": str(cfg.get("title") or "Form"),
        }
        
        def _apply_tokens(s: str) -> str:
            out = s or ""
            for k, v in tokens.items():
                out = out.replace(k, v or "")
            return out
        
        subject = _apply_tokens(subject_tpl)
        content_html = _apply_tokens(body_tpl)
        
        # Get branding and font settings
        theme = cfg.get("theme") or {}
        branding = cfg.get("branding") or {}
        font_href = theme.get("fontUrl") or None
        font_family = theme.get("fontFamily") or None
        footer_html = (cfg.get("autoReplyFooterHtml") or "").strip() or None
        
        # Render email with client template
        html = render_email("client_base.html", {
            "subject": subject,
            "title": subject,
            "preheader": None,
            "intro": None,
            "content_html": content_html,
            "footer_html": footer_html,
            "font_href": font_href,
            "font_family": font_family,
            "brand_logo": branding.get("logo") or None,
            "brand_name": cfg.get("title") or ""
        })
        
        # Try to send via user's email integration first, then fall back to default
        sent_via_integration = False
        if owner_id:
            try:
                sent_via_integration = _send_email_via_integration(owner_id, to_email, subject, html)
            except Exception as e:
                logger.debug("Email integration failed, falling back to default: %s", str(e))
        
        if not sent_via_integration:
            send_email_html(to_email, subject, html)
        
        logger.info("Auto-reply email sent successfully to=%s form=%s", to_email, cfg.get("id"))
        return True
        
    except Exception as e:
        logger.exception("Auto-reply email failed: %s", str(e))
        return False


@router.post("/builder/forms/{form_id}/notify-client")
@limiter.limit("60/minute")
async def notify_client(form_id: str, request: Request, payload: Dict[str, Any] | None = None):
    """Send a client notification email for a form.

    Body: { to: string, subject?: string, html?: string, text?: string, fullName?: string }
    If subject/html are omitted, falls back to form auto-reply config.
    """
    payload = payload or {}
    # Accept several ways to specify recipient
    to_raw = str(payload.get("to") or payload.get("email") or "").strip()
    subject = str(payload.get("subject") or "").strip()
    html = str(payload.get("html") or "").strip()
    text_fallback = str(payload.get("text") or "").strip()
    full_name = str(payload.get("fullName") or "").strip()

    # If recipient not provided, try to extract from latest submission (for auto-reply)
    if not to_raw:
        response_id = str(payload.get("responseId") or "").strip()
        if response_id:
            try:
                async with async_session_maker() as session:
                    res = await session.execute(
                        text("""
                            SELECT data
                            FROM submissions
                            WHERE id = :response_id AND form_id = :form_id
                            LIMIT 1
                        """),
                        {"response_id": response_id, "form_id": form_id}
                    )
                    row = res.mappings().first()
                    if row:
                        import json
                        submission_data = row.get("data")
                        if isinstance(submission_data, str):
                            submission_data = json.loads(submission_data)
                        # Look for email field in submission data
                        for key, value in (submission_data or {}).items():
                            if isinstance(value, str) and "@" in value and "." in value:
                                to_raw = value.strip()
                                break
            except Exception as e:
                logger.error(f"Failed to extract email from submission: {e}")
        
        if not to_raw:
            # Don't send anything - this endpoint is for CLIENT auto-replies only
            # Owner notifications are handled separately in submit_form endpoint
            raise HTTPException(status_code=400, detail="Client email not found in submission data")

    # Validate email format
    try:
        _validate_email(to_raw, allow_smtputf8=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid email address")

    # Load auto-reply settings from form config (Thank You Email tab in builder)
    # This takes priority over any defaults
    button_label = None
    button_url = None
    button_color = None
    try:
        async with async_session_maker() as session:
            res = await session.execute(
                text(
                    """
                    SELECT title, auto_reply_enabled, auto_reply_subject, auto_reply_message_html, theme, branding
                    FROM forms
                    WHERE id = :fid
                    LIMIT 1
                    """
                ),
                {"fid": form_id},
            )
            row = res.mappings().first()
            if row and bool(row.get("auto_reply_enabled")):
                # Use form owner's configured auto-reply settings
                if not subject:
                    subject = str(row.get("auto_reply_subject") or "Thank you for your submission").strip()
                if not html:
                    html = str(row.get("auto_reply_message_html") or "").strip()
                
                # Load button customization from theme JSONB
                import json
                theme = row.get("theme")
                if theme:
                    if isinstance(theme, str):
                        theme = json.loads(theme)
                    button_label = theme.get("autoReplyButtonLabel") or "Visit Website"
                    button_url = theme.get("autoReplyButtonUrl") or ""
                    button_color = theme.get("autoReplyButtonColor") or "#4f46e5"
                
                # Get logo from branding for email template
                branding = row.get("branding")
                logo_url = None
                if branding:
                    if isinstance(branding, str):
                        branding = json.loads(branding)
                    logo_url = branding.get("logo")
    except Exception as e:
        logger.error(f"Failed to load auto-reply settings: {e}")
        # Continue with defaults if form config fails
    
    # Final fallbacks if still empty after loading form config
    if not subject:
        subject = "Thank you for your submission"
    if not html:
        if text_fallback:
            html = f"<pre style='white-space: pre-wrap; font-family: sans-serif;'>{text_fallback}</pre>"
        else:
            html = "<p>Thank you for your submission!</p>"
    
    # Wrap in email template with branding and custom button
    email_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin: 0; padding: 20px; background-color: #0B0F19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
        <div style="max-width: 600px; margin: 0 auto;">
            {'<div style="text-align: center; margin-bottom: 20px;">' + f'<img src="{logo_url}" alt="Logo" style="max-width: 160px; height: auto;">' + '</div>' if logo_url else ''}
            <div style="background-color: #111418; border-radius: 12px; padding: 24px;">
                <div style="color: #ffffff; font-size: 16px; line-height: 1.6;">
                    {html}
                </div>
                {f'<div style="margin-top: 24px; text-align: center;"><a href="{button_url}" style="display: inline-block; background-color: {button_color}; color: #ffffff; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 14px;">{button_label}</a></div>' if button_url and button_label else ''}
            </div>
            <div style="text-align: center; margin-top: 16px; color: #c7c7c7; font-size: 12px;">
                © {__import__('datetime').datetime.now().year} CleanEnroll
            </div>
        </div>
    </body>
    </html>
    """

    try:
        send_email_html(to_raw, subject, email_html)
        return {"ok": True}
    except Exception as e:
        logger.exception("notify_client failed form_id=%s to=%s", form_id, to_raw)
        raise HTTPException(status_code=500, detail=f"Failed to send: {e}")
