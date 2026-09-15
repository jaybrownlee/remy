"""Local magic-link authentication with opaque, hashed, single-use credentials."""

import hashlib
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    delete,
    event,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from remy.db.migrate import require_current

metadata = MetaData()
organizations = Table(
    "auth_organizations",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(120), nullable=False),
)
users = Table(
    "auth_users",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("email", String(254), nullable=False, unique=True),
)
memberships = Table(
    "auth_memberships",
    metadata,
    Column("user_id", ForeignKey("auth_users.id"), primary_key=True),
    Column("org_id", ForeignKey("auth_organizations.id"), primary_key=True),
    Column("role", String(10), nullable=False),
    CheckConstraint("role IN ('owner', 'member')"),
)
links = Table(
    "auth_links",
    metadata,
    Column("digest", String(64), primary_key=True),
    Column("user_id", ForeignKey("auth_users.id"), nullable=False),
    Column("browser_digest", String(64), nullable=False),
    Column("expires", Integer, nullable=False, index=True),
)
sessions = Table(
    "auth_sessions",
    metadata,
    Column("digest", String(64), primary_key=True),
    Column("user_id", ForeignKey("auth_users.id"), nullable=False),
    Column("org_id", ForeignKey("auth_organizations.id"), nullable=False),
    Column("csrf", String(64), nullable=False),
    Column("expires", Integer, nullable=False, index=True),
)
limits = Table(
    "auth_rate_limits",
    metadata,
    Column("key", String(100), primary_key=True),
    Column("count", Integer, nullable=False),
    Column("expires", Integer, nullable=False, index=True),
)
audit = Table(
    "auth_audit",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("user_id", String(36), nullable=False),
    Column("org_id", String(36), nullable=False),
    Column("action", String(40), nullable=False),
    Column("target", String(100), nullable=False),
    Column("created", Integer, nullable=False),
)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def normalize_email(value: str) -> str:
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(
        r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}", value
    ):
        raise ValueError("Enter a valid email address.")
    return value


@dataclass(frozen=True)
class Identity:
    user_id: str
    org_id: UUID
    email: str
    organization: str
    role: str
    csrf: str


class AuthStore:
    def __init__(self, database_url: str) -> None:
        self.engine = create_engine(database_url)
        if self.engine.dialect.name == "sqlite":

            @event.listens_for(self.engine, "connect")
            def enable_foreign_keys(connection: sqlite3.Connection, record: object) -> None:
                connection.execute("PRAGMA foreign_keys=ON")

        require_current(self.engine)

    def record(self, identity: Identity, action: str, target: str = "") -> None:
        with self.engine.begin() as conn:
            self._record(conn, identity, action, target)

    @staticmethod
    def _record(conn: Connection, identity: Identity, action: str, target: str = "") -> None:
        conn.execute(
            insert(audit).values(
                id=str(uuid4()),
                user_id=identity.user_id,
                org_id=str(identity.org_id),
                action=action,
                target=target,
                created=int(time.time()),
            )
        )

    def provision(
        self, email: str, name: str, org_id: UUID | None = None, role: str = "owner"
    ) -> UUID:
        """Operator-only provisioning; no organization IDs are accepted by login."""
        email = normalize_email(email)
        if role not in {"owner", "member"} or not name.strip() or len(name) > 120:
            raise ValueError("Invalid organization or role.")
        with self.engine.begin() as conn:
            if org_id is None:
                org_id = uuid4()
                conn.execute(insert(organizations).values(id=str(org_id), name=name.strip()))
            elif not conn.scalar(
                select(organizations.c.id).where(organizations.c.id == str(org_id))
            ):
                raise ValueError("Organization does not exist.")
            user_id = conn.scalar(select(users.c.id).where(users.c.email == email))
            if not user_id:
                user_id = str(uuid4())
                conn.execute(insert(users).values(id=user_id, email=email))
            conn.execute(insert(memberships).values(user_id=user_id, org_id=str(org_id), role=role))
            identity = Identity(str(user_id), org_id, email, name, role, "")
            self._record(conn, identity, "operator_provision")
        return org_id

    def _allow(self, key: str, maximum: int, now: int) -> bool:
        key = f"{now // 3600}:{digest(key)}"
        try:
            with self.engine.begin() as conn:
                conn.execute(
                    insert(limits).values(key=key, count=0, expires=(now // 3600 + 1) * 3600)
                )
        except IntegrityError:
            pass
        with self.engine.begin() as conn:
            count = conn.scalar(
                update(limits)
                .where(
                    limits.c.key == key,
                    limits.c.count < maximum,
                )
                .values(count=limits.c.count + 1)
                .returning(limits.c.count)
            )
            return count is not None

    def issue(self, email: str, browser: str, peer: str, now: int | None = None) -> str | None:
        now = int(time.time()) if now is None else now
        if not self._allow("peer:" + peer, 20, now):
            return None
        try:
            email = normalize_email(email)
        except ValueError:
            return None
        if not self._allow("email:" + email, 5, now):
            return None
        with self.engine.begin() as conn:
            user_id = conn.scalar(
                select(users.c.id).join(memberships).where(users.c.email == email)
            )
            if not user_id:
                return None
            token = secrets.token_urlsafe(32)
            conn.execute(
                insert(links).values(
                    digest=digest(token),
                    user_id=user_id,
                    browser_digest=digest(browser),
                    expires=now + 900,
                )
            )
            return token

    def consume(self, token: str, browser: str, now: int | None = None) -> str | None:
        now = int(time.time()) if now is None else now
        if not browser or len(token) > 100:
            return None
        with self.engine.begin() as conn:
            user_id = conn.scalar(
                delete(links)
                .where(
                    links.c.digest == digest(token),
                    links.c.browser_digest == digest(browser),
                    links.c.expires > now,
                )
                .returning(links.c.user_id)
            )
            if not user_id:
                return None
            org_id = conn.scalar(
                select(memberships.c.org_id)
                .where(
                    memberships.c.user_id == user_id,
                )
                .order_by(memberships.c.org_id)
            )
            if not org_id:
                return None
            value = secrets.token_urlsafe(32)
            conn.execute(
                insert(sessions).values(
                    digest=digest(value),
                    user_id=user_id,
                    org_id=org_id,
                    csrf=secrets.token_urlsafe(32),
                    expires=now + 28800,
                )
            )
            self._record(conn, Identity(str(user_id), UUID(org_id), "", "", "", ""), "login")
            return value

    def identify(self, token: str, now: int | None = None) -> Identity | None:
        now = int(time.time()) if now is None else now
        if not token or len(token) > 100:
            return None
        with self.engine.connect() as conn:
            row = conn.execute(
                select(
                    users.c.id,
                    sessions.c.org_id,
                    users.c.email,
                    organizations.c.name,
                    memberships.c.role,
                    sessions.c.csrf,
                )
                .select_from(
                    sessions.join(users)
                    .join(
                        memberships,
                        (memberships.c.user_id == sessions.c.user_id)
                        & (memberships.c.org_id == sessions.c.org_id),
                    )
                    .join(organizations, organizations.c.id == sessions.c.org_id)
                )
                .where(
                    sessions.c.digest == digest(token),
                    sessions.c.expires > now,
                )
            ).first()
        return Identity(str(row[0]), UUID(row[1]), row[2], row[3], row[4], row[5]) if row else None

    def logout(self, token: str, identity: Identity) -> None:
        with self.engine.begin() as conn:
            conn.execute(delete(sessions).where(sessions.c.digest == digest(token)))
            self._record(conn, identity, "logout")

    def organization_choices(self, identity: Identity) -> list[tuple[str, str]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(organizations.c.id, organizations.c.name)
                .join(memberships)
                .where(memberships.c.user_id == identity.user_id)
                .order_by(organizations.c.name, organizations.c.id)
            ).all()
        return [(row[0], row[1]) for row in rows]

    def switch(self, token: str, org_id: UUID, now: int | None = None) -> tuple[str, int] | None:
        """Atomically rotate the session, checking both current and target memberships."""
        now = int(time.time()) if now is None else now
        current_member = (
            select(memberships.c.user_id)
            .where(
                memberships.c.user_id == sessions.c.user_id,
                memberships.c.org_id == sessions.c.org_id,
            )
            .exists()
        )
        target_member = (
            select(memberships.c.user_id)
            .where(
                memberships.c.user_id == sessions.c.user_id,
                memberships.c.org_id == str(org_id),
            )
            .exists()
        )
        with self.engine.begin() as conn:
            row = conn.execute(
                delete(sessions)
                .where(
                    sessions.c.digest == digest(token),
                    sessions.c.expires > now,
                    current_member,
                    target_member,
                )
                .returning(sessions.c.user_id, sessions.c.expires, sessions.c.org_id)
            ).first()
            if row is None:
                return None
            value = secrets.token_urlsafe(32)
            conn.execute(
                insert(sessions).values(
                    digest=digest(value),
                    user_id=row[0],
                    org_id=str(org_id),
                    csrf=secrets.token_urlsafe(32),
                    expires=row[1],
                )
            )
            identity = Identity(row[0], UUID(row[2]), "", "", "", "")
            self._record(conn, identity, "organization_switch", str(org_id))
            return value, row[1] - now

    def cleanup(self, now: int | None = None) -> dict[str, int]:
        """Remove at most 1,000 expired rows per table; never touch audit history."""
        now = int(time.time()) if now is None else now
        counts = {}
        with self.engine.begin() as conn:
            for table, key in (
                (links, links.c.digest),
                (sessions, sessions.c.digest),
                (limits, limits.c.key),
            ):
                expired = select(key).where(table.c.expires <= now).limit(1000)
                removed = conn.execute(delete(table).where(key.in_(expired)).returning(key)).all()
                counts[table.name] = len(removed)
        return counts
