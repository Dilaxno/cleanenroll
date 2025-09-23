import os
import logging
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime
import json
import urllib.request
import urllib.error

try:
    import resend  # type: ignore
    _RESEND_AVAILABLE = True
except Exception:
    resend = None  # type: ignore
    _RESEND_AVAILABLE = False

# Email configuration from environment (Resend only)
SMTP_FROM = os.getenv("SMTP_FROM", "no-reply@cleanenroll.com")

# Resend configuration
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM = os.getenv("RESEND_FROM", SMTP_FROM)

# Debugging
EMAIL_DEBUG = os.getenv("EMAIL_DEBUG", "false").lower() in ("1", "true", "yes", "on")

# Centralized logger for email utils
logger = logging.getLogger("backend.email")

def _elog(msg: str):
    if EMAIL_DEBUG:
        logger.debug(msg)

_templates_env = Environment(
    loader=FileSystemLoader(os.path.join(os.getcwd(), "backend", "templates", "email")),
    autoescape=select_autoescape(["html", "xml"]),
)


def render_email(template_name: str, context: dict) -> str:
    template = _templates_env.get_template(template_name)
    base_context = {"year": datetime.utcnow().year}
    base_context.update(context or {})
    return template.render(**base_context)


def send_email_html(to_email: str, subject: str, html_body: str):
    """
    Send email using Resend only (no SMTP fallback).

    Environment variables:
      - RESEND_API_KEY: Required. Resend API key
      - RESEND_FROM: Optional custom from for Resend (defaults to SMTP_FROM)
    """
    if not RESEND_API_KEY:
        logger.error("Resend API key missing; cannot send email")
        raise RuntimeError("Email is not configured. Provide RESEND_API_KEY.")

    try:
        if _RESEND_AVAILABLE:
            resend.api_key = RESEND_API_KEY  # type: ignore[attr-defined]
            payload = {
                "from": RESEND_FROM,
                "to": [to_email],
                "subject": subject,
                "html": html_body,
            }
            _elog(f"Using Resend SDK. From={RESEND_FROM}, To={to_email}")
            result = resend.Emails.send(payload)  # type: ignore[attr-defined]
            msg_id = None
            try:
                msg_id = result.get('id') if isinstance(result, dict) else getattr(result, 'id', None)
            except Exception:
                msg_id = None
            _elog(f"Resend accepted email id={msg_id or 'unknown'}")
            return
        else:
            # HTTP API when SDK not installed
            payload = {
                "from": RESEND_FROM,
                "to": [to_email],
                "subject": subject,
                "html": html_body,
            }
            _elog(f"Using Resend HTTP. From={RESEND_FROM}, To={to_email}")
            req = urllib.request.Request(
                url="https://api.resend.com/emails",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status in (200, 201, 202):
                    _elog(f"Resend accepted email with status {resp.status}")
                    return
                raise RuntimeError(f"Resend returned unexpected status {resp.status}")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8")
        except Exception:
            body = str(e)
        logger.warning("Resend HTTPError %s: %s", getattr(e, 'code', 'n/a'), body)
        raise RuntimeError("Failed to send email via Resend")
    except Exception as ex:
        logger.exception("Resend send failed: %s", ex)
        raise RuntimeError("Failed to send email via Resend")
