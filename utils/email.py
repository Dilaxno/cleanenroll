import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime

# Email configuration from environment
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "no-reply@cleanenroll.com")

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
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        raise RuntimeError("SMTP is not configured. Please set SMTP_HOST, SMTP_USER, SMTP_PASS env vars.")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = SMTP_FROM
    msg['To'] = to_email

    # Plaintext fallback
    msg.attach(MIMEText("This email requires an HTML-capable client.", 'plain', 'utf-8'))
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
