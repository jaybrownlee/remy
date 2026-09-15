import shutil
import smtplib
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor
from email import message_from_bytes
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from remy.api.app import create_app
from remy.auth import links
from remy.mail import DeliveryError, LocalMailbox, SMTPDelivery, configured_delivery


def test_real_tls_smtp_exchange_over_private_socketpair(tmp_path, monkeypatch):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL CLI is required for the ephemeral test certificate")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ],
        check=True,
        timeout=15,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    trusted_context = ssl.create_default_context()
    trusted_context.load_verify_locations(cafile=str(cert))
    monkeypatch.setattr(ssl, "create_default_context", lambda: trusted_context)
    client_socket, server_socket = socket.socketpair()
    client_socket.settimeout(5)
    server_socket.settimeout(5)
    received = []

    class SocketSMTP(smtplib.SMTP_SSL):
        def _get_socket(self, host, port, timeout):
            return self.context.wrap_socket(client_socket, server_hostname=host)

    monkeypatch.setattr(smtplib, "SMTP_SSL", SocketSMTP)

    def server():
        with (
            server_context.wrap_socket(server_socket, server_side=True) as connection,
            connection.makefile("rwb") as stream,
        ):

            def reply(value):
                stream.write(value)
                stream.flush()

            reply(b"220 localhost test SMTP\r\n")
            authenticated = False
            while line := stream.readline():
                if line.startswith(b"ehlo "):
                    reply(b"250-localhost\r\n250 AUTH PLAIN\r\n")
                elif line.startswith(b"AUTH PLAIN "):
                    authenticated = True
                    reply(b"235 authenticated\r\n")
                elif line.startswith((b"mail FROM:", b"rcpt TO:")):
                    assert authenticated
                    reply(b"250 accepted\r\n")
                elif line == b"data\r\n":
                    reply(b"354 send message\r\n")
                    body = bytearray()
                    while (part := stream.readline()) != b".\r\n":
                        assert part
                        body.extend(part)
                    received.append(message_from_bytes(bytes(body)))
                    reply(b"250 queued\r\n")
                elif line == b"QUIT\r\n":
                    reply(b"221 goodbye\r\n")
                    return
                else:
                    raise AssertionError("Unexpected SMTP command")

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            exchange = pool.submit(server)
            SMTPDelivery("localhost", 465, "user", "secret", "sender@example.com", "tls")(
                "recipient@example.com", "https://localhost/login/confirm?token=wire-test"
            )
            exchange.result(timeout=10)
    finally:
        client_socket.close()
        server_socket.close()
    assert len(received) == 1 and received[0]["To"] == "recipient@example.com"
    assert b"wire-test" in received[0].get_payload(decode=True)


@pytest.mark.parametrize("security", ["starttls", "tls"])
def test_smtp_encrypts_before_auth_and_sends_only_link(monkeypatch, security):
    calls = []
    messages = []

    class Client:
        def __init__(self, host, port, timeout, context=None):
            assert (host, port, timeout) == ("smtp.example.com", 587, 10)
            if security == "tls":
                assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            calls.append("connect")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            calls.append("close")

        def ehlo(self):
            calls.append("ehlo")

        def starttls(self, context):
            assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            calls.append("tls")

        def login(self, username, password):
            assert username == "user" and password == "secret"
            calls.append("auth")

        def send_message(self, message):
            calls.append("send")
            messages.append(message)
            return {}

    monkeypatch.setattr(smtplib, "SMTP", Client)
    monkeypatch.setattr(smtplib, "SMTP_SSL", Client)
    delivery = SMTPDelivery(
        "smtp.example.com", 587, "user", "secret", "sender@example.com", security
    )
    delivery("recipient@example.com", "https://localhost/login/confirm?token=test-token")
    assert calls == (
        ["connect", "ehlo", "tls", "ehlo", "auth", "send", "close"]
        if security == "starttls"
        else ["connect", "ehlo", "auth", "send", "close"]
    )
    assert messages[0]["To"] == "recipient@example.com"
    assert messages[0]["From"] == "sender@example.com"
    assert "test-token" in messages[0].get_content()
    assert "secret" not in str(messages[0]) and "secret" not in repr(delivery)


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("private detail"),
        smtplib.SMTPAuthenticationError(535, b"secret"),
        ssl.SSLCertVerificationError("secret"),
    ],
)
def test_transport_errors_are_sanitized(monkeypatch, error):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(smtplib, "SMTP", fail)
    with pytest.raises(DeliveryError, match="^Email delivery failed.$"):
        SMTPDelivery("smtp.example.com", 587, "user", "secret", "sender@example.com")(
            "recipient@example.com", "https://localhost/link"
        )


def test_starttls_failure_never_sends_credentials(monkeypatch):
    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ehlo(self):
            pass

        def starttls(self, context):
            raise smtplib.SMTPNotSupportedError("No TLS")

        def login(self, *args):
            pytest.fail("Credentials must not be sent without TLS")

    monkeypatch.setattr(smtplib, "SMTP", Client)
    with pytest.raises(DeliveryError):
        SMTPDelivery("smtp.example.com", 587, "user", "secret", "sender@example.com")(
            "recipient@example.com", "https://localhost/link"
        )


def test_configuration_fails_closed_and_local_mail_permissions(tmp_path):
    settings = {
        "REMY_MAIL_MODE": "smtp",
        "REMY_SMTP_HOST": "smtp.example.com",
        "REMY_SMTP_USERNAME": "user",
        "REMY_SMTP_PASSWORD": "secret",
        "REMY_SMTP_FROM": "sender@example.com",
    }
    assert isinstance(configured_delivery(settings), SMTPDelivery)
    for key in ("REMY_SMTP_HOST", "REMY_SMTP_USERNAME", "REMY_SMTP_PASSWORD", "REMY_SMTP_FROM"):
        invalid = {k: v for k, v in settings.items() if k != key}
        with pytest.raises(ValueError, match="missing or invalid"):
            configured_delivery(invalid)
    for key, value in [
        ("REMY_SMTP_SECURITY", "plain"),
        ("REMY_SMTP_PORT", "0"),
        ("REMY_SMTP_FROM", "sender@example.com\r\nBcc: victim@example.com"),
    ]:
        with pytest.raises(ValueError):
            configured_delivery(settings | {key: value})
    with pytest.raises(ValueError):
        configured_delivery({"REMY_MAIL_MODE": "typo"})
    mailbox = configured_delivery({"REMY_DATA_DIR": str(tmp_path)})
    assert isinstance(mailbox, LocalMailbox)
    mailbox("a@example.com", "http://localhost/test")
    assert (tmp_path / "mail").stat().st_mode & 0o777 == 0o700
    assert next((tmp_path / "mail").iterdir()).stat().st_mode & 0o777 == 0o600


def test_delivery_failure_revokes_link_and_keeps_response_generic(database_url, caplog):
    attempted = []

    def fail(email, url):
        attempted.append(url)
        raise DeliveryError("sensitive server response")

    app = create_app(database_url, demo_mode=False, deliver=fail)
    app.state.auth.provision("member@example.com", "Member")
    with TestClient(app, base_url="http://localhost") as client:
        page = client.get("/login")
        assert "SameSite=lax" in page.headers["set-cookie"]
        nonce = client.cookies.get("remy_login")
        failed = client.post("/login/new", data={"email": "member@example.com", "csrf": nonce})
        unknown = client.post("/login/new", data={"email": "missing@example.com", "csrf": nonce})
        assert failed.text == unknown.text and failed.status_code == 200
        assert "private server mailbox" not in failed.text
        token = parse_qs(urlsplit(attempted[0]).query)["token"][0]
        assert app.state.auth.consume(token, nonce) is None
        with app.state.auth.engine.connect() as conn:
            assert conn.execute(select(links)).all() == []
        assert "magic_link_delivery_failed" in caplog.text
        for private in [token, "member@example.com", "sensitive server response"]:
            assert private not in caplog.text and private not in failed.text
