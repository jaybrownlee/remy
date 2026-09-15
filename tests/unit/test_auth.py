import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import DatabaseError

from remy.api.app import create_app
from remy.auth import AuthStore, audit, links, memberships, sessions


def csrf(response):
    return re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)


def login(client, mailbox, email):
    form = client.get("/login")
    result = client.post("/login/new", data={"email": email, "csrf": csrf(form)})
    assert result.status_code == 200
    token = parse_qs(urlsplit(mailbox[-1][1]).query)["token"][0]
    page = client.get("/login/confirm", params={"token": token})
    result = client.post("/login/confirm", data={"token": token, "csrf": csrf(page)})
    assert result.status_code == 200
    return result


def test_expiry_replay_browser_binding_and_hash_storage(database_url):
    auth = AuthStore(database_url)
    auth.provision("a@example.com", "A")
    token = auth.issue("A@example.com", "browser", "peer", now=100)
    assert token
    assert auth.consume(token, "different", now=101) is None
    assert auth.consume(token, "browser", now=1000) is None
    session = auth.consume(token, "browser", now=999)
    assert session
    assert auth.consume(token, "browser", now=999) is None
    assert auth.identify(session, now=1000)
    assert auth.identify(session, now=999 + 28800) is None
    with auth.engine.connect() as conn:
        stored = repr(conn.execute(select(sessions)).all()) + repr(
            conn.execute(select(links)).all()
        )
    assert session not in stored and token not in stored


def test_only_one_concurrent_consumer_can_sign_in(database_url):
    auth = AuthStore(database_url)
    auth.provision("a@example.com", "A")
    token = auth.issue("a@example.com", "browser", "peer")
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: auth.consume(token, "browser"), range(2)))
    assert sum(result is not None for result in outcomes) == 1


def test_rate_limits_and_revocation(database_url):
    auth = AuthStore(database_url)
    org = auth.provision("a@example.com", "A")
    tokens = [auth.issue("a@example.com", "browser", "peer", now=100) for _ in range(6)]
    assert all(tokens[:5]) and tokens[-1] is None
    session = auth.consume(tokens[0], "browser", now=101)
    assert auth.identify(session, now=102)
    with auth.engine.begin() as conn:
        conn.execute(delete(memberships).where(memberships.c.org_id == str(org)))
    assert auth.identify(session, now=102) is None


def test_audit_database_rejects_mutation(database_url):
    auth = AuthStore(database_url)
    auth.provision("a@example.com", "A")
    for statement in [delete(audit), update(audit).values(action="tampered")]:
        with pytest.raises(DatabaseError), auth.engine.begin() as conn:
            conn.execute(statement)


def test_membership_foreign_keys_are_enforced(database_url):
    auth = AuthStore(database_url)
    with pytest.raises(DatabaseError), auth.engine.begin() as conn:
        conn.execute(insert(memberships).values(user_id="missing", org_id="missing", role="owner"))


def test_confirmation_query_is_redacted_and_https_cookie_is_secure(database_url):
    mailbox = []
    observed = []
    app = create_app(
        database_url,
        demo_mode=False,
        public_url="https://localhost",
        deliver=lambda email, url: mailbox.append((email, url)),
    )
    app.state.auth.provision("a@example.com", "A")

    async def wrapper(scope, receive, send):
        async def inspect(message):
            if scope["type"] == "http" and scope["path"] == "/login/confirm":
                observed.append(scope["query_string"])
            await send(message)

        await app(scope, receive, inspect)

    with TestClient(wrapper, base_url="https://localhost") as client:
        login(client, mailbox, "a@example.com")
        assert observed and all(query == b"" for query in observed)
        assert all(cookie.secure for cookie in client.cookies.jar)
        page = client.get("/")
        # A valid session does not bypass upload CSRF validation.
        assert (
            client.post("/reports/import", files={"file": ("scan.json", b"[]")}).status_code == 403
        )
        assert (
            client.post(
                "/reports/import",
                data={"csrf": csrf(page)},
                files={
                    "file": ("scan.json", Path("remy/data/prowler-aws-example.json").read_bytes())
                },
                follow_redirects=False,
            ).status_code
            == 303
        )


def test_authenticated_report_tenants_csrf_logout_and_download_audit(database_url):
    mailbox = []
    app = create_app(
        database_url,
        demo_mode=False,
        deliver=lambda email, url: mailbox.append((email, url)),
    )
    app.state.auth.provision("a@example.com", "Alpha")
    app.state.auth.provision("b@example.com", "Beta")
    with (
        TestClient(app, base_url="http://localhost") as a,
        TestClient(app, base_url="http://localhost") as b,
    ):
        assert a.get("/", follow_redirects=False).headers["location"] == "/login"
        assert a.post("/reports/sample").status_code == 401
        page = login(a, mailbox, "a@example.com")
        assert "Alpha" in page.text
        assert a.post("/reports/sample").status_code == 403
        created = a.post("/reports/sample", data={"csrf": csrf(page)}, follow_redirects=False)
        assert created.status_code == 303
        path = created.headers["location"]
        assert a.get(path).status_code == 200
        login(b, mailbox, "b@example.com")
        for suffix in ["", "/download/json", "/download/pdf", "/download/terraform"]:
            assert b.get(path + suffix).status_code == 404
            assert a.get(path + suffix).status_code == 200
        with app.state.auth.engine.connect() as conn:
            actions = conn.execute(select(audit.c.action)).scalars().all()
        assert actions.count("report_download") == 3
        session = a.cookies.get("remy_session")
        assert a.post("/logout", data={"csrf": csrf(a.get("/"))}).status_code == 200
        assert app.state.auth.identify(session) is None


def test_login_does_not_disclose_membership_or_accept_get_consumption(database_url):
    mailbox = []
    app = create_app(
        database_url,
        demo_mode=False,
        deliver=lambda email, url: mailbox.append((email, url)),
    )
    app.state.auth.provision("a@example.com", "A")
    with TestClient(app, base_url="http://localhost") as client:
        nonce = csrf(client.get("/login"))
        known = client.post("/login/new", data={"email": "a@example.com", "csrf": nonce})
        unknown = client.post("/login/new", data={"email": "missing@example.com", "csrf": nonce})
        assert known.text == unknown.text
        assert len(mailbox) == 1
        token = parse_qs(urlsplit(mailbox[0][1]).query)["token"][0]
        client.get("/login/confirm", params={"token": token})
        assert client.cookies.get("remy_session") is None
        assert (
            client.post("/login/confirm", data={"token": token, "csrf": "bad"}).status_code == 403
        )
        assert client.post("/login/confirm", data={"token": token, "csrf": "☃"}).status_code == 403
        result = client.post(
            "/login/confirm", data={"token": token, "csrf": nonce}, follow_redirects=False
        )
        assert result.status_code == 303
        assert "HttpOnly" in result.headers["set-cookie"]
        assert "SameSite=strict" in result.headers["set-cookie"]
