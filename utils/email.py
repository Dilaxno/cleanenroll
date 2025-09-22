import os
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime
import json
import urllib.request
import urllib.error

# Email configuration from environment
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
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
    Send email using Resend (preferred) or fallback to SMTP if Resend is not configured.

    Environment variables:
      - RESEND_API_KEY: If present, use Resend API
      - RESEND_FROM: Optional custom from for Resend (defaults to SMTP_FROM)
      - SMTP_*: Fallback SMTP credentials
    """

    # Try Resend first if configured
    if RESEND_API_KEY:
        try:
            payload = {
                "from": RESEND_FROM,
                "to": [to_email],
                "subject": subject,
                "html": html_body,
            }
            _elog(f"Using Resend provider. From={RESEND_FROM}, To={to_email}")
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
                # 200/201 are considered success by Resend
                if resp.status not in (200, 201, 202):
                    # fall through to SMTP
                    _elog(f"Resend returned status {resp.status}, falling back to SMTP")
                else:
                    _elog(f"Resend accepted email with status {resp.status}")
                    return
        except urllib.error.HTTPError as e:
            # Log and fall back to SMTP
            try:
                body = e.read().decode("utf-8")
            except Exception:
                body = str(e)
            logger.warning("Resend HTTPError %s: %s", getattr(e, 'code', 'n/a'), body)
        except Exception as ex:
            # Fall back to SMTP silently
            logger.warning("Resend request failed: %s; falling back to SMTP", ex)

    # Fallback to SMTP if Resend not configured or failed
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        logger.error("Email not configured: missing SMTP credentials and no RESEND_API_KEY")
        raise RuntimeError(
            "Email is not configured. Provide RESEND_API_KEY (preferred) or SMTP_HOST/SMTP_USER/SMTP_PASS."
        )

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = SMTP_FROM
    msg['To'] = to_email

    # Plaintext fallback
    msg.attach(MIMEText("This email requires an HTML-capable client.", 'plain', 'utf-8'))
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    _elog(f"Using SMTP provider host={SMTP_HOST} port={SMTP_PORT} user={'***' if SMTP_USER else ''}")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.ehlo()
        try:
            server.starttls()
            _elog("SMTP STARTTLS successful")
        except Exception as e:
            logger.debug("SMTP STARTTLS skipped/failed: %s", e)
        server.login(SMTP_USER, SMTP_PASS)
        _elog("SMTP AUTH successful, sending message")
        server.send_message(msg)
        _elog("SMTP send complete")
