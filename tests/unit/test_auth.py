import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

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


def test_cleanup_keeps_active_credentials_and_audit(database_url):
    auth = AuthStore(database_url)
    auth.provision("a@example.com", "A")
    expired = auth.consume(
        auth.issue("a@example.com", "browser", "peer", now=100), "browser", now=100
    )
    auth.issue("a@example.com", "browser", "peer", now=100)
    active_link = auth.issue("a@example.com", "browser", "peer", now=30000)
    active = auth.consume(
        auth.issue("a@example.com", "browser", "peer", now=30000), "browser", now=30000
    )
    with auth.engine.connect() as conn:
        before = conn.execute(select(audit)).all()
    removed = auth.cleanup(now=30000)
    assert removed == {"auth_links": 1, "auth_sessions": 1, "auth_rate_limits": 2}
    assert auth.cleanup(now=30000) == dict.fromkeys(removed, 0)
    assert auth.identify(expired, now=30000) is None
    assert auth.identify(active, now=30000)
    with auth.engine.connect() as conn:
        assert conn.execute(select(audit)).all() == before
    assert auth.consume(active_link, "browser", now=30000)


def test_switch_rotates_once_preserves_expiry_and_rejects_nonmembers(database_url):
    auth = AuthStore(database_url)
    auth.provision("a@example.com", "A")
    auth.provision("a@example.com", "B")
    token = auth.consume(
        auth.issue("a@example.com", "browser", "peer", now=100), "browser", now=100
    )
    identity = auth.identify(token, now=100)
    target = next(
        UUID(id) for id, _ in auth.organization_choices(identity) if UUID(id) != identity.org_id
    )
    assert auth.switch(token, uuid4(), now=101) is None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: auth.switch(token, target, now=101), range(2)))
    successes = [result for result in results if result]
    assert len(successes) == 1
    new, remaining = successes[0]
    assert remaining == 28799
    assert auth.identify(token, now=101) is None
    changed = auth.identify(new, now=101)
    assert changed.org_id == target and changed.csrf != identity.csrf
    assert auth.identify(new, now=28900) is None
    with auth.engine.begin() as conn:
        conn.execute(delete(memberships).where(memberships.c.org_id == str(target)))
    assert auth.switch(new, identity.org_id, now=102) is None


def test_browser_switch_requires_csrf_and_changes_report_scope(database_url):
    mailbox = []
    app = create_app(database_url, demo_mode=False, deliver=lambda e, u: mailbox.append((e, u)))
    auth = app.state.auth
    auth.provision("a@example.com", "A")
    auth.provision("a@example.com", "B")
    with TestClient(app, base_url="http://localhost") as client:
        assert client.post("/organizations/switch").status_code == 401
        page = login(client, mailbox, "a@example.com")
        old_csrf = csrf(page)
        identity = auth.identify(client.cookies.get("remy_session"))
        target = next(
            id for id, _ in auth.organization_choices(identity) if UUID(id) != identity.org_id
        )
        report = client.post(
            "/reports/sample", data={"csrf": old_csrf}, follow_redirects=False
        ).headers["location"]
        assert target in client.get("/organizations").text
        assert client.post("/organizations/switch", data={"org_id": target}).status_code == 403
        assert (
            client.post(
                "/organizations/switch", data={"org_id": str(uuid4()), "csrf": old_csrf}
            ).status_code
            == 404
        )
        switched = client.post("/organizations/switch", data={"org_id": target, "csrf": old_csrf})
        assert switched.status_code == 200
        assert client.get(report).status_code == 404
        assert client.get(report + "/download/json").status_code == 404
        assert client.post("/reports/sample", data={"csrf": old_csrf}).status_code == 403
        assert (
            client.post(
                "/organizations/switch",
                data={"org_id": str(identity.org_id), "csrf": csrf(switched)},
            ).status_code
            == 200
        )
        assert client.get(report).status_code == 200
