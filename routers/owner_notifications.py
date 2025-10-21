from fastapi import APIRouter
import logging
import os
import urllib.parse
from typing import Dict, Any, Optional
from sqlalchemy import text
from db.database import async_session_maker
from utils.email import render_email, send_email_html

router = APIRouter()
logger = logging.getLogger(__name__)


def _normalize_bg_public_url(url: str) -> str:
    """Normalize R2 URLs to use custom domain if available."""
    try:
        r2_public = os.getenv("R2_PUBLIC_BASE", "").strip()
        if r2_public and url and ".r2.dev" in url:
            parsed = urllib.parse.urlparse(url)
            path_part = parsed.path
            return f"{r2_public.rstrip('/')}{path_part}"
        return url
    except Exception:
        return url


def _shorten_url(url: str) -> str:
    """Shorten URL for display purposes."""
    try:
        if len(url) > 80:
            return url[:77] + "..."
        return url
    except Exception:
        return url


async def get_owner_email(owner_id: str) -> Optional[str]:
    """
    Fetch the owner's email from Neon DB by user ID.
    
    Args:
        owner_id: The user ID (uid) of the form owner
        
    Returns:
        Owner's email address or None if not found
    """
    if not owner_id:
        return None
        
    try:
        async with async_session_maker() as session:
            res = await session.execute(
                text("SELECT email FROM users WHERE uid = :uid LIMIT 1"),
                {"uid": owner_id}
            )
            row = res.mappings().first()
            if row and row.get("email"):
                email = str(row.get("email")).strip()
                if "@" in email:
                    logger.debug("Fetched owner email for notifications owner_id=%s", owner_id)
                    return email
    except Exception as e:
        logger.warning("Failed to fetch owner email owner_id=%s: %s", owner_id, str(e))
    
    return None


async def send_owner_notification(
    owner_email: str,
    form_id: str,
    form_data: Dict[str, Any],
    submission_record: Dict[str, Any]
) -> bool:
    """
    Send email notification to form owner about a new submission.
    
    Args:
        owner_email: Email address of the form owner
        form_id: ID of the form that received a submission
        form_data: Form configuration data
        submission_record: The submission data including answers
        
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        if not owner_email:
            logger.warning("Owner email not provided for notification form_id=%s", form_id)
            return False
            
        logger.info("Preparing owner email notification to=%s form_id=%s", owner_email, form_id)
        
        form_title = str(form_data.get("title") or "Form").strip() or "Form"
        subject = f"New submission — {form_title}"
        preview = ""
        
        # Build email preview from submission answers
        # Note: Answers now use field labels as keys (not IDs) per submission storage update
        try:
            ans = submission_record.get("answers") or {}
            logger.debug("Building email preview from %d answers", len(ans))
            
            parts = []
            for label, v in list(ans.items())[:10]:
                try:
                    # Keys are already field labels, use directly
                    field_label = str(label).strip() if label else "Field"
                    
                    if isinstance(v, str) and v.strip():
                        val_preview = v.strip()[:140]
                        parts.append(f"<p><strong>{field_label}:</strong> {val_preview}</p>")
                    elif isinstance(v, list) and v:
                        list_str = ", ".join(str(x) for x in v if x)
                        if list_str:
                            parts.append(f"<p><strong>{field_label}:</strong> {list_str[:140]}</p>")
                    elif isinstance(v, dict):
                        # Handle complex objects like addresses
                        dict_str = ", ".join(f"{k}: {val}" for k, val in v.items() if val)
                        if dict_str:
                            parts.append(f"<p><strong>{field_label}:</strong> {dict_str[:140]}</p>")
                except Exception:
                    continue
            
            preview = "".join(parts)
            logger.debug("Email preview built with %d field parts", len(parts))
        except Exception as e:
            logger.warning("Failed to build email preview: %s", str(e))
            preview = ""
        
        # Add signature thumbnails if available
        try:
            sigs = submission_record.get("signatures") or {}
        except Exception:
            sigs = {}
        
        sigs_html = ""
        if isinstance(sigs, dict) and sigs:
            items = []
            for k, v in sigs.items():
                try:
                    url = (v.get("pngUrl") or v.get("url") or v.get("pngDataUrl") or v.get("dataUrl") or "").strip()
                    if url:
                        safe = _normalize_bg_public_url(url) if url.startswith("http") else url
                        link = _shorten_url(safe) if safe.startswith("http") else safe
                        items.append(
                            f"<div style='margin:6px 0'>"
                            f"<div style='font-size:12px;color:#94a3b8'>Signature {k}</div>"
                            f"<a href='{link}' target='_blank' rel='noopener noreferrer'>"
                            f"<img src='{safe}' alt='Signature {k}' style='max-width:320px;border:1px solid #e5e7eb;border-radius:6px' /></a>"
                            + (f"<div style='font-size:12px;color:#94a3b8;word-break:break-all'>{link}</div>" if link and isinstance(link, str) and link.startswith('http') else "")
                            + "</div>"
                        )
                except Exception:
                    continue
            
            if items:
                sigs_html = (
                    "<div style='margin-top:12px'>"
                    "<div style='font-weight:600;margin-bottom:6px'>Signatures</div>"
                    + "".join(items)
                    + "</div>"
                )
        
        # Render and send email
        html = render_email("base.html", {
            "subject": subject,
            "title": subject,
            "intro": f"You received a new submission for {form_title}.",
            "content_html": (preview or "<p>No preview available</p>") + sigs_html,
            "preheader": f"New submission for {form_title}",
        })
        
        logger.info("Sending owner notification email to=%s subject=%s", owner_email, subject)
        send_email_html(owner_email, subject, html)
        logger.info("Owner notification email sent successfully to=%s form_id=%s", owner_email, form_id)
        
        return True
        
    except Exception as e:
        logger.exception("Owner email notification failed form_id=%s owner_email=%s error=%s", form_id, owner_email, str(e))
        return False
