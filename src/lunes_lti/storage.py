"""SQLite storage: the PyLTI1p3 launch data storage (nonce, state, cached launch) and the launches of this service.

A new connection per operation keeps it safe with several gunicorn workers and threads; the load of a tool that is
launched from course pages is small.
"""

import json
import sqlite3
import time
import typing as t
import uuid
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from pylti1p3.launch_data_storage.base import LaunchDataStorage

SCHEMA = """
CREATE TABLE IF NOT EXISTS lti_data (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at REAL
);
CREATE TABLE IF NOT EXISTS launches (
    id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    -- Pseudonymous user ID of the LMS; no names or e-mail addresses (NFR-04, NFR-10)
    subject TEXT NOT NULL,
    context_id TEXT,
    resource_link_id TEXT NOT NULL,
    -- AGS line item of the resource link
    lineitem TEXT,
    -- AGS endpoint claim as JSON (scopes, line item URLs), for grade passback
    ags_endpoint TEXT,
    -- Page of the LMS to return to (launch_presentation.return_url)
    return_url TEXT,
    job_id INTEGER NOT NULL,
    unit_id INTEGER NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    -- Role in the course: learner, instructor or other (FR-01); only learners get grades
    role TEXT NOT NULL DEFAULT 'learner'
);
"""


def connect(database_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(database_path)) as connection, connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(SCHEMA)
        _migrate(connection)


def _migrate(connection: sqlite3.Connection) -> None:
    """Adds columns introduced after the first version to an existing database."""
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(launches)")}
    for column in ("return_url", "ags_endpoint"):
        if column not in columns:
            connection.execute(f"ALTER TABLE launches ADD COLUMN {column} TEXT")
    if "role" not in columns:
        # Launches stored before the role was read were treated as learners
        connection.execute("ALTER TABLE launches ADD COLUMN role TEXT NOT NULL DEFAULT 'learner'")


class SqliteLaunchDataStorage(LaunchDataStorage[t.Any]):
    """Launch data storage of PyLTI1p3 in SQLite. Create one instance per request.

    Keys are prefixed with a session ID from the cookie ``lti1p3-session-id`` (set at login, see
    ``LaunchDataStorage``), so a nonce or state is only valid in the browser that started the login.
    """

    def __init__(self, database_path: Path) -> None:
        super().__init__()
        self._database_path = database_path

    def can_set_keys_expiration(self) -> bool:
        return True

    def get_value(self, key: str) -> t.Any:
        with closing(connect(self._database_path)) as connection:
            row = connection.execute(
                "SELECT value FROM lti_data WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)",
                (self._prepare_key(key), time.time()),
            ).fetchone()
        return json.loads(row["value"]) if row else None

    def set_value(self, key: str, value: t.Any, exp: int | None = None) -> None:
        now = time.time()
        with closing(connect(self._database_path)) as connection, connection:
            connection.execute("DELETE FROM lti_data WHERE expires_at <= ?", (now,))
            connection.execute(
                "INSERT OR REPLACE INTO lti_data (key, value, expires_at) VALUES (?, ?, ?)",
                (self._prepare_key(key), json.dumps(value), now + exp if exp else None),
            )

    def check_value(self, key: str) -> bool:
        return self.get_value(key) is not None


@dataclass(frozen=True)
class Launch:
    id: str
    issuer: str
    client_id: str
    deployment_id: str
    subject: str
    context_id: str | None
    resource_link_id: str
    lineitem: str | None
    ags_endpoint: str | None
    return_url: str | None
    job_id: int
    unit_id: int
    created_at: float
    expires_at: float
    role: str = "learner"


def create_launch(database_path: Path, lifetime: int, **fields: t.Any) -> Launch:
    now = time.time()
    launch = Launch(id=str(uuid.uuid4()), created_at=now, expires_at=now + lifetime, **fields)
    columns = list(launch.__dataclass_fields__)
    with closing(connect(database_path)) as connection, connection:
        connection.execute("DELETE FROM launches WHERE expires_at <= ?", (now,))
        connection.execute(
            f"INSERT INTO launches ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            [getattr(launch, column) for column in columns],
        )
    return launch


def get_launch(database_path: Path, launch_id: str) -> Launch | None:
    with closing(connect(database_path)) as connection:
        row = connection.execute(
            "SELECT * FROM launches WHERE id = ? AND expires_at > ?", (launch_id, time.time())
        ).fetchone()
    return Launch(**dict(row)) if row else None
