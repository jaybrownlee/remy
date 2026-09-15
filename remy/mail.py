"""Private local mailbox and TLS-only authenticated SMTP delivery."""

import os
import smtplib
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from uuid import uuid4

from remy.auth import normalize_email


class DeliveryError(Exception):
    """A delivery attempt failed; never include transport details or credentials."""


class LocalMailbox:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def __call__(self, email: str, url: str) -> None:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.directory / f"{uuid4()}.txt"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(f"To: {email}\nRemy sign-in link (expires in 15 minutes):\n{url}\n")


@dataclass(frozen=True, repr=False)
class SMTPDelivery:
    host: str
    port: int
    username: str
    password: str
    sender: str
    security: str = "starttls"

    def __post_init__(self) -> None:
        if (
            not self.host
            or any(character.isspace() for character in self.host)
            or not 1 <= self.port <= 65535
            or self.security not in {"starttls", "tls"}
            or not self.username
            or not self.password
            or not self.username.isascii()
            or not self.password.isascii()
        ):
            raise ValueError(
                "Invalid SMTP configuration; check host, port, TLS mode, and credentials."
            )
        normalize_email(self.sender)

    def __call__(self, email: str, url: str) -> None:
        message = EmailMessage()
        message["From"] = normalize_email(self.sender)
        message["To"] = normalize_email(email)
        message["Subject"] = "Sign in to Remy"
        message["Date"] = formatdate(usegmt=True)
        message["Message-ID"] = make_msgid(domain=self.sender.rsplit("@", 1)[-1])
        message.set_content(
            "Open this link in the browser where you requested it, within 15 minutes.\n"
            f"Confirm sign-in on the page. The link can be used only once.\n\n{url}\n\n"
            "If you did not request this link, ignore this message.\n"
        )
        context = ssl.create_default_context()
        try:
            client = (
                smtplib.SMTP_SSL(self.host, self.port, timeout=10, context=context)
                if self.security == "tls"
                else smtplib.SMTP(self.host, self.port, timeout=10)
            )
            with client:
                client.ehlo()
                if self.security == "starttls":
                    client.starttls(context=context)
                    client.ehlo()
                client.login(self.username, self.password)
                if client.send_message(message):
                    raise DeliveryError("Email delivery failed.")
        except OSError:
            # Includes SMTP exceptions, timeouts, and certificate validation errors.
            raise DeliveryError("Email delivery failed.") from None


def configured_delivery(settings: Mapping[str, str] | None = None) -> Callable[[str, str], None]:
    settings = os.environ if settings is None else settings
    mode = settings.get("REMY_MAIL_MODE", "local")
    if mode == "local":
        return LocalMailbox(Path(settings.get("REMY_DATA_DIR", ".remy")) / "mail")
    if mode != "smtp":
        raise ValueError("REMY_MAIL_MODE must be local or smtp.")
    security = settings.get("REMY_SMTP_SECURITY", "starttls")
    try:
        port = int(settings.get("REMY_SMTP_PORT", "465" if security == "tls" else "587"))
        return SMTPDelivery(
            host=settings["REMY_SMTP_HOST"],
            port=port,
            username=settings["REMY_SMTP_USERNAME"],
            password=settings["REMY_SMTP_PASSWORD"],
            sender=settings["REMY_SMTP_FROM"],
            security=security,
        )
    except (KeyError, ValueError):
        raise ValueError(
            "SMTP configuration is missing or invalid; see the email runbook."
        ) from None
