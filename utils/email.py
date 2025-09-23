import os
import logging
from jinja2 import Environment, FileSystemLoader, select_autoescape, TemplateNotFound
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

from pathlib import Path

# Build robust template search paths (CWD-based, file-based, and env override)
template_search_paths = []
try:
    template_search_paths.append(str((Path(os.getcwd()).resolve() / "backend" / "templates" / "email")))
except Exception:
    pass
try:
    template_search_paths.append(str((Path(__file__).resolve().parents[1] / "templates" / "email")))
except Exception:
    pass
_env_dir = os.getenv("EMAIL_TEMPLATE_DIR")
if _env_dir:
    template_search_paths.append(_env_dir)

_elog(f"Email template search paths: {template_search_paths}")
_templates_env = Environment(
    loader=FileSystemLoader(template_search_paths),
    autoescape=select_autoescape(["html", "xml"]),
)


def render_email(template_name: str, context: dict) -> str:
    try:
        template = _templates_env.get_template(template_name)
    except TemplateNotFound as e:
        logger.error("Email template '%s' not found. Paths searched: %s", template_name, template_search_paths)
        raise
    base_context = {"year": datetime.utcnow().year}
    base_context.update(context or {})
    return template.render(**base_context)


import smtplib
import ssl
from email.message import EmailMessage

def send_email_html(to_email: str, subject: str, html_body: str):
    """
    Send email using Resend via SMTP (STARTTLS by default).

    Environment variables:
      - SMTP_HOST: SMTP server host (default: smtp.resend.com)
      - SMTP_PORT: SMTP server port (default: 587 for STARTTLS)
      - SMTP_USER: SMTP username (Resend recommends 'resend')
      - RESEND_API_KEY or SMTP_PASSWORD: SMTP password (use your Resend API key)
      - RESEND_FROM / SMTP_FROM: From address
    """
    host = os.getenv("SMTP_HOST", "smtp.resend.com")
    try:
        port = int(os.getenv("SMTP_PORT", "587") or "587")
    except ValueError:
        port = 587
    username = os.getenv("SMTP_USER", "resend")
    password = os.getenv("RESEND_API_KEY") or os.getenv("SMTP_PASSWORD", "")

    from_addr = RESEND_FROM or SMTP_FROM

    if not password:
        logger.error("SMTP password / RESEND_API_KEY missing; cannot send email")
        raise RuntimeError("Email is not configured. Provide RESEND_API_KEY or SMTP_PASSWORD.")

    # Build MIME email with plain-text fallback
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content("This email contains HTML content. If you see this, please view in an HTML-capable client.")
    msg.add_alternative(html_body, subtype="html")

    try:
        if port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as server:
                server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.ehlo()
                # Use STARTTLS for port 587
                context = ssl.create_default_context()
                server.starttls(context=context)
                server.ehlo()
                server.login(username, password)
                server.send_message(msg)
        _elog(f"SMTP send ok via {host}:{port} from={from_addr} to={to_email}")
    except smtplib.SMTPResponseException as e:
        code = getattr(e, 'smtp_code', None)
        err = getattr(e, 'smtp_error', b'').decode('utf-8', 'ignore') if isinstance(getattr(e, 'smtp_error', b''), (bytes, bytearray)) else str(getattr(e, 'smtp_error', ''))
        logger.warning("SMTP error %s: %s", code, err)
        raise RuntimeError("Failed to send email via SMTP")
    except Exception as ex:
        logger.exception("SMTP send failed: %s", ex)
        raise RuntimeError("Failed to send email via SMTP")
