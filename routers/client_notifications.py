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

    # If direct recipient not provided, try to derive from submission values using fieldId or form config
    if not to_raw:
        raise HTTPException(status_code=400, detail="Recipient email is required.")

    if not subject:
        subject = "Notification"
    if not html:
        if text_fallback:
            html = f"<pre style='white-space: pre-wrap; font-family: sans-serif;'>{text_fallback}</pre>"
        else:
            html = "<p>You have a new notification.</p>"
    
    # Validate email format
    try:
        _validate_email(to_raw, allow_smtputf8=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid email address")

    # If subject/html not provided, attempt to load from form auto-reply config
    if not subject or not html:
        try:
            async with async_session_maker() as session:
                res = await session.execute(
                    text(
                        """
                        SELECT title, auto_reply_enabled, auto_reply_subject, auto_reply_message_html
                        FROM forms
                        WHERE id = :fid
                        LIMIT 1
                        """
                    ),
                    {"fid": form_id},
                )
                row = res.mappings().first()
                if row and bool(row.get("auto_reply_enabled")):
                    if not subject:
                        subject = str(row.get("auto_reply_subject") or "Thank you for your submission").strip()
                    if not html:
                        html = str(row.get("auto_reply_message_html") or "").strip()
        except Exception:
            # best-effort; continue
            pass

    try:
        send_email_html(to_raw, subject, html)
        return {"ok": True}
    except Exception as e:
        logger.exception("notify_client failed form_id=%s to=%s", form_id, to_raw)
        raise HTTPException(status_code=500, detail=f"Failed to send: {e}")
