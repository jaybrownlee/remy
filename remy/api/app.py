"""Loopback-only saved-scan application with local magic-link authentication."""

import os
import secrets
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from remy.auth import AuthStore, Identity
from remy.db.store import Store
from remy.ingest.ocsf import MAX_BYTES, ImportError
from remy.mail import LocalMailbox
from remy.reports.compose import compose_report
from remy.reports.export import json_export, pdf_export, terraform_export
from remy.reports.schema import Report

ROOT = Path(__file__).resolve().parents[1]
DEMO_ORG = UUID("7cae2ed8-eab8-4c63-bd3b-f57b1d661205")


class LocalBoundary:
    """Reject remote peers, cross-origin writes, and oversized requests before parsing."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        peer = scope.get("client")
        if peer and peer[0] not in {"127.0.0.1", "::1", "testclient"}:
            await Response("Local prototype: remote access is disabled.", status_code=403)(
                scope, receive, send
            )
            return
        if scope["method"] in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = headers.get(b"origin")
            try:
                source = urlsplit(origin.decode()) if origin else None
                host = headers.get(b"host", b"").decode()
            except (ValueError, UnicodeDecodeError):
                await Response("Invalid origin.", status_code=403)(scope, receive, send)
                return
            if source and (source.scheme not in {"http", "https"} or source.netloc != host):
                await Response("Cross-origin writes are disabled.", status_code=403)(
                    scope, receive, send
                )
                return
            if headers.get(b"sec-fetch-site") == b"cross-site":
                await Response("Cross-site writes are disabled.", status_code=403)(
                    scope, receive, send
                )
                return
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                body.extend(message.get("body", b""))
                if len(body) > MAX_BYTES + 65536:
                    await Response("Upload exceeds 10 MiB.", status_code=413)(scope, receive, send)
                    return
                if not message.get("more_body", False):
                    break
            delivered = False

            async def replay() -> Message:
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, replay, send)
        else:
            await self.app(scope, receive, send)


def create_app(
    database_url: str | None = None,
    *,
    demo_mode: bool | None = None,
    deliver: Callable[[str, str], None] | None = None,
    public_url: str | None = None,
) -> FastAPI:
    demo_mode = (os.environ.get("REMY_DEMO_MODE") == "1") if demo_mode is None else demo_mode
    origin_url = "http://127.0.0.1:8000"
    if public_url is not None:
        origin_url = public_url
    elif "REMY_PUBLIC_URL" in os.environ:
        origin_url = os.environ["REMY_PUBLIC_URL"]
    parsed = urlsplit(origin_url)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
    ):
        raise ValueError("This checkpoint requires a loopback public_url.")
    origin_url = origin_url.rstrip("/")
    secure_cookie = parsed.scheme == "https"
    database_url = database_url or os.environ.get("REMY_DATABASE_URL")
    if database_url is None:
        directory = Path(os.environ.get("REMY_DATA_DIR", ".remy"))
        directory.mkdir(parents=True, exist_ok=True)
        database_url = f"sqlite:///{directory / 'reports.db'}"
    store = Store(database_url)
    auth = AuthStore(database_url)
    deliver = deliver or LocalMailbox(Path(os.environ.get("REMY_DATA_DIR", ".remy")) / "mail")
    app = FastAPI(title="Remy local prototype", docs_url=None, redoc_url=None)
    app.state.store = store
    app.state.auth = auth
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])
    app.add_middleware(LocalBoundary)
    app.mount("/static", StaticFiles(directory=ROOT / "api" / "static"), name="static")
    templates = Jinja2Templates(directory=ROOT / "api" / "templates")

    @app.middleware("http")
    async def security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.scope["path"] == "/login/confirm":
            # Uvicorn logs the shared scope at response start. Remove credentials first.
            query = request.scope.get("query_string", b"")[:4096].decode("ascii", errors="ignore")
            request.state.login_token = parse_qs(query).get("token", [""])[0][:100]
            request.scope["query_string"] = b""
        identity = auth.identify(request.cookies.get("remy_session", "")) if not demo_mode else None
        request.state.identity = identity
        protected = (
            request.url.path == "/"
            or request.url.path.startswith("/reports")
            or request.url.path == "/logout"
        )
        if protected and not demo_mode and identity is None:
            response = (
                RedirectResponse("/login", status_code=303)
                if request.method == "GET"
                else Response("Sign in required.", status_code=401)
            )
        else:
            response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'none'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def organization(request: Request) -> UUID:
        if demo_mode:
            return DEMO_ORG
        identity: Identity | None = request.state.identity
        if identity is None:
            raise HTTPException(401, "Sign in required.")
        return identity.org_id

    async def check_csrf(request: Request, expected: str) -> None:
        form = await request.form()
        supplied = form.get("csrf", "")
        if (
            not expected
            or not isinstance(supplied, str)
            or not secrets.compare_digest(expected.encode(), supplied.encode())
        ):
            raise HTTPException(403, "Invalid form token. Reload the page and try again.")

    @app.get("/login", response_class=HTMLResponse)
    def login(request: Request) -> Response:
        browser = secrets.token_urlsafe(32)
        response = templates.TemplateResponse(
            request=request, name="login.html", context={"csrf": browser}
        )
        response.set_cookie(
            "remy_login",
            browser,
            max_age=900,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
        )
        return response

    @app.post("/login/new")
    async def request_link(request: Request) -> Response:
        browser = request.cookies.get("remy_login", "")
        await check_csrf(request, browser)
        form = await request.form()
        email = str(form.get("email", ""))[:255]
        peer = request.client.host if request.client else "unknown"
        token = auth.issue(email, browser, peer)
        if token:
            try:
                assert deliver is not None
                deliver(email.strip().lower(), f"{origin_url}/login/confirm?token={token}")
            except OSError:
                # Never include the token, recipient, or transport exception in the response.
                pass
        return templates.TemplateResponse(
            request=request, name="login.html", context={"sent": True}
        )

    @app.get("/login/confirm", response_class=HTMLResponse)
    def confirm_link(request: Request) -> Response:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "confirm": True,
                "token": request.state.login_token,
                "csrf": request.cookies.get("remy_login", ""),
            },
        )

    @app.post("/login/confirm")
    async def consume_link(request: Request) -> Response:
        browser = request.cookies.get("remy_login", "")
        await check_csrf(request, browser)
        form = await request.form()
        value = auth.consume(str(form.get("token", "")), browser)
        if value is None:
            return Response(
                "This link is invalid or expired. Request a new link in this browser.",
                status_code=400,
            )
        old = request.cookies.get("remy_session", "")
        previous = auth.identify(old)
        if previous:
            auth.logout(old, previous)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            "remy_session",
            value,
            max_age=28800,
            httponly=True,
            secure=secure_cookie,
            samesite="strict",
        )
        response.delete_cookie("remy_login")
        return response

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        identity = request.state.identity
        if identity:
            await check_csrf(request, identity.csrf)
            auth.logout(request.cookies.get("remy_session", ""), identity)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie("remy_session")
        return response

    def home(request: Request, error: str | None = None, status: int = 200) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"reports": store.list(organization(request)), "error": error},
            status_code=status,
        )

    def fetch(request: Request, report_id: UUID) -> Report:
        report = store.get(organization(request), report_id)
        if report is None:
            raise HTTPException(404, "Report not found.")
        return report

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return home(request)

    @app.get("/healthz")
    def health() -> dict[str, object]:
        store.list(DEMO_ORG)
        return {"ok": True, "db": True, "mode": "local-prototype", "redis": "not_used"}

    @app.post("/reports/sample")
    async def sample(request: Request) -> RedirectResponse:
        if not demo_mode:
            await check_csrf(request, request.state.identity.csrf)
        raw = (ROOT / "data" / "prowler-aws-example.json").read_bytes()
        report = compose_report(
            raw, organization(request), "Prowler public AWS example", sample=True
        )
        store.save(report)
        return RedirectResponse(f"/reports/{report.report_id}", status_code=303)

    @app.post("/reports/import", response_model=None)
    async def import_report(request: Request, file: UploadFile) -> Response:
        if not demo_mode:
            await check_csrf(request, request.state.identity.csrf)
        raw = await file.read(MAX_BYTES + 1)
        await file.close()
        # Use a basename as display text only; never construct a filesystem path from it.
        name = (file.filename or "Imported scan").replace("\\", "/").rsplit("/", 1)[-1][:120]
        try:
            report = compose_report(raw, organization(request), name)
        except ImportError as error:
            return home(request, str(error), status=400)
        store.save(report)
        return RedirectResponse(f"/reports/{report.report_id}", status_code=303)

    @app.get("/reports/{report_id}", response_class=HTMLResponse)
    def show(request: Request, report_id: UUID) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name="report.html", context={"report": fetch(request, report_id)}
        )

    @app.get("/reports/{report_id}/download/{kind}")
    def download(request: Request, report_id: UUID, kind: str) -> Response:
        report = fetch(request, report_id)
        if kind == "json":
            data, media, suffix = json_export(report), "application/json", "json"
        elif kind == "pdf":
            data, media, suffix = pdf_export(report), "application/pdf", "pdf"
        elif kind == "terraform":
            data, media, suffix = terraform_export(report), "application/zip", "zip"
        else:
            raise HTTPException(404, "Download format not found.")
        if request.state.identity:
            auth.record(request.state.identity, "report_download", f"{report_id}:{kind}")
        return Response(
            data,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="remy-{report_id}.{suffix}"'},
        )

    return app
