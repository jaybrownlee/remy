# Email delivery

Remy defaults to the private local mailbox. Authenticated SMTP delivery is available without selecting a particular email provider. No SMTP account, paid service, DNS record, or external recipient has been configured by this implementation.

## Configuration

Supply these settings through the runtime environment or a secret manager, never committed files. Restart Remy after changing them.

| Setting | Value |
| --- | --- |
| `REMY_MAIL_MODE` | `local` (default) or `smtp` |
| `REMY_SMTP_HOST` | Provider's SMTP hostname; required for SMTP |
| `REMY_SMTP_PORT` | Defaults to 587 for STARTTLS or 465 for implicit TLS |
| `REMY_SMTP_SECURITY` | `starttls` (default) or `tls`; plaintext is rejected |
| `REMY_SMTP_USERNAME` | Provider-issued SMTP username |
| `REMY_SMTP_PASSWORD` | Provider-issued SMTP password, kept secret |
| `REMY_SMTP_FROM` | Single verified sender email address, without a display name |
| `REMY_PUBLIC_URL` | Browser's canonical loopback origin for this local checkpoint |

Missing or invalid SMTP settings stop startup; they do not silently select local delivery. The client requires certificate and hostname verification, authenticates only after TLS, and uses ten-second socket-operation timeouts. Delivery runs in a worker thread so SMTP waits do not block the ASGI event loop. SMTP debugging is never enabled. The implementation uses Python's [SMTP client](https://docs.python.org/3.12/library/smtplib.html).

Only the sign-in link and explanatory text are sent, not report data or findings. The requesting browser receives an HttpOnly, SameSite=Lax nonce cookie so a top-level email-link GET can carry it. The GET does not sign in; the confirmation POST requires the nonce and same-origin checks. Authenticated session cookies remain SameSite=Strict. Links still expire after 15 minutes and cannot be transferred to a different browser.

## Failure handling

Timeouts, certificate errors, SMTP authentication errors, and rejected recipients are treated as delivery failures. The issued link is revoked, the response remains generic, and the operational log receives only `magic_link_delivery_failed`—no recipient, token, URL, transport response, or traceback.

There are no automatic retries. A lost SMTP acknowledgment can leave delivery uncertain, so even a message that arrives after a reported transport failure may contain a revoked link. Request a fresh link after the provider is healthy. Rate limits still apply. A successful SMTP acknowledgment means the provider accepted the message, not that it reached the inbox. Bounce/webhook processing and an outbox worker are not implemented.

If failures occur, check provider availability, verified-sender status, authentication, and certificate configuration through the provider's controls. Do not enable SMTP debug output or capture request bodies to investigate. Alerting infrastructure must consume the generic failure event; no external alert destination is configured.

## Acceptance

Tests cover STARTTLS ordering, certificate-verifying contexts, implicit TLS, credential redaction, missing configuration, failure responses, and failed-link revocation on both databases. A local test performs a real TLS handshake, SMTP authentication exchange, and message transfer over a private socket pair using an ephemeral trusted test certificate. It sends no external email.

To validate your provider, supply credentials and a verified sender, then request a link for a provisioned address you control. Confirm receipt, same-browser login, replay rejection, and provider failure handling. Configure sender-domain authentication with that provider before customer delivery. The application remains loopback-only; external hosting, public callback URLs, proxy security, and deployment acceptance are separate work.
