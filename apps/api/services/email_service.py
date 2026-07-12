"""
apps/api/services/email_service.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real, minimal email sending -- no third-party SDK, just Python's stdlib
smtplib/email, gated entirely on the WILLIAM_SMTP_* environment variables
already declared (unset) in .env.example. When they're unset, this module
never pretends to send mail: callers get an honest
`status: "external_dependency_required"` result, matching the same
provider-routing convention used by agents/voice_agent's STT/TTS/speaker-
recognition engines.

Never logs or returns raw SMTP credentials.
"""

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Any, Dict, Optional

logger = logging.getLogger("william.api.services.email_service")


def dependency_status() -> str:
    if os.getenv("WILLIAM_SMTP_HOST") and os.getenv("WILLIAM_SMTP_FROM_EMAIL"):
        return "configured"
    return "external_dependency_required"


def send_email(*, to_email: str, subject: str, body_text: str, body_html: Optional[str] = None) -> Dict[str, Any]:
    """
    Sends a real email via SMTP when WILLIAM_SMTP_HOST/WILLIAM_SMTP_FROM_EMAIL
    are configured. Otherwise returns a structured, honest
    external_dependency_required result -- never a fake "sent" claim.
    """
    if dependency_status() != "configured":
        return {
            "success": False,
            "status": "external_dependency_required",
            "message": "No SMTP provider configured (WILLIAM_SMTP_HOST/WILLIAM_SMTP_FROM_EMAIL unset).",
        }

    host = os.getenv("WILLIAM_SMTP_HOST", "")
    port = int(os.getenv("WILLIAM_SMTP_PORT", "587") or "587")
    username = os.getenv("WILLIAM_SMTP_USERNAME", "")
    password = os.getenv("WILLIAM_SMTP_PASSWORD", "")
    use_tls = (os.getenv("WILLIAM_SMTP_USE_TLS", "true").strip().lower() not in {"0", "false", "no"})
    from_email = os.getenv("WILLIAM_SMTP_FROM_EMAIL", "")
    from_name = os.getenv("WILLIAM_SMTP_FROM_NAME", "William AI")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{from_name} <{from_email}>"
    message["To"] = to_email
    message.set_content(body_text)
    if body_html:
        message.add_alternative(body_html, subtype="html")

    try:
        with smtplib.SMTP(host, port, timeout=15) as client:
            if use_tls:
                client.starttls()
            if username and password:
                client.login(username, password)
            client.send_message(message)

        return {"success": True, "status": "sent", "message": f"Email sent to {to_email}."}
    except Exception as exc:  # noqa: BLE001 -- must never crash the caller over an SMTP failure
        logger.warning("send_email failed: %s", exc)
        return {"success": False, "status": "send_failed", "message": "Email could not be sent.", "detail": str(exc)}
