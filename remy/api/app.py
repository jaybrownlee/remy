"""Loopback-only saved-scan prototype; production authentication is not implemented."""

import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from remy.db.store import Store
from remy.ingest.ocsf import MAX_BYTES, ImportError
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


def create_app(database_url: str | None = None) -> FastAPI:
    database_url = database_url or os.environ.get("REMY_DATABASE_URL")
    if database_url is None:
        directory = Path(os.environ.get("REMY_DATA_DIR", ".remy"))
        directory.mkdir(parents=True, exist_ok=True)
        database_url = f"sqlite:///{directory / 'reports.db'}"
    store = Store(database_url)
    app = FastAPI(title="Remy local prototype", docs_url=None, redoc_url=None)
    app.state.store = store
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])
    app.add_middleware(LocalBoundary)
    app.mount("/static", StaticFiles(directory=ROOT / "api" / "static"), name="static")
    templates = Jinja2Templates(directory=ROOT / "api" / "templates")

    @app.middleware("http")
    async def security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'none'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    def home(request: Request, error: str | None = None, status: int = 200) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"reports": store.list(DEMO_ORG), "error": error},
            status_code=status,
        )

    def fetch(report_id: UUID) -> Report:
        report = store.get(DEMO_ORG, report_id)
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
    def sample() -> RedirectResponse:
        raw = (ROOT / "data" / "prowler-aws-example.json").read_bytes()
        report = compose_report(raw, DEMO_ORG, "Prowler public AWS example", sample=True)
        store.save(report)
        return RedirectResponse(f"/reports/{report.report_id}", status_code=303)

    @app.post("/reports/import", response_model=None)
    async def import_report(request: Request, file: UploadFile) -> Response:
        raw = await file.read(MAX_BYTES + 1)
        await file.close()
        # Use a basename as display text only; never construct a filesystem path from it.
        name = (file.filename or "Imported scan").replace("\\", "/").rsplit("/", 1)[-1][:120]
        try:
            report = compose_report(raw, DEMO_ORG, name)
        except ImportError as error:
            return home(request, str(error), status=400)
        store.save(report)
        return RedirectResponse(f"/reports/{report.report_id}", status_code=303)

    @app.get("/reports/{report_id}", response_class=HTMLResponse)
    def show(request: Request, report_id: UUID) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name="report.html", context={"report": fetch(report_id)}
        )

    @app.get("/reports/{report_id}/download/{kind}")
    def download(report_id: UUID, kind: str) -> Response:
        report = fetch(report_id)
        if kind == "json":
            data, media, suffix = json_export(report), "application/json", "json"
        elif kind == "pdf":
            data, media, suffix = pdf_export(report), "application/pdf", "pdf"
        elif kind == "terraform":
            data, media, suffix = terraform_export(report), "application/zip", "zip"
        else:
            raise HTTPException(404, "Download format not found.")
        return Response(
            data,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="remy-{report_id}.{suffix}"'},
        )

    return app


app = create_app()
