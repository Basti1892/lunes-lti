"""Tests without key generation."""

import time

import jwt
import pytest

from lunes_lti import create_app, keys
from lunes_lti.config import Config

from lunes_lti import lti, session_token, storage
from lunes_lti.config import load_config

SECRET = b"test-secret-not-used-anywhere-else"


def test_load_config_resolves_data_dir_relative_to_file(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        """
base_url = "http://localhost:8080/"
data_dir = "data"

[[platforms]]
issuer = "https://lms.example.org"
client_id = "abc"
auth_login_url = "https://lms.example.org/auth"
auth_token_url = "https://lms.example.org/token"
key_set_url = "https://lms.example.org/certs"
deployment_ids = ["1"]
""",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.base_url == "http://localhost:8080"
    assert config.launch_url == "http://localhost:8080/lti/launch"
    assert config.cookie_path == "/lti/"
    assert config.data_dir == tmp_path / "data"
    assert config.platforms[0].deployment_ids == ["1"]
    assert config.token_lifetime == 7200


def test_cookie_path_includes_base_path(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('base_url = "https://example.org/lunes"', encoding="utf-8")
    assert load_config(path).cookie_path == "/lunes/lti/"


def test_session_token_round_trip():
    token = session_token.issue(SECRET, "launch-1", lifetime=60)
    assert session_token.verify(SECRET, token) == "launch-1"


def test_session_token_rejects_expired_and_foreign_tokens():
    expired = jwt.encode(
        {"iss": "lunes-lti", "lid": "x", "iat": int(time.time()) - 120, "exp": int(time.time()) - 60},
        SECRET,
        algorithm="HS256",
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        session_token.verify(SECRET, expired)
    with pytest.raises(jwt.InvalidSignatureError):
        session_token.verify(b"another-secret-of-sufficient-length", session_token.issue(SECRET, "x", 60))


def test_minimise_removes_personal_claims():
    data = {
        "sub": "42",
        "name": "A",
        "email": "a@example.org",
        lti.CLAIM + "ext": {"user_username": "a"},
        lti.CLAIM + "lis": {"person_sourcedid": "a"},
        lti.CUSTOM_CLAIM: {"job_id": "1"},
    }
    assert lti.minimise(data) == {"sub": "42", lti.CUSTOM_CLAIM: {"job_id": "1"}}


def test_launch_data_storage_with_session_and_expiry(tmp_path):
    database = tmp_path / "db.sqlite3"
    storage.init_db(database)

    first = storage.SqliteLaunchDataStorage(database)
    first.set_session_id("browser-a")
    first.set_value("lti1p3-nonce-n", True, exp=60)
    first.set_value("lti1p3-old", True, exp=-1)

    other = storage.SqliteLaunchDataStorage(database)
    other.set_session_id("browser-b")

    assert first.check_value("lti1p3-nonce-n")
    assert not other.check_value("lti1p3-nonce-n")
    assert first.get_value("lti1p3-old") is None


def test_launches(tmp_path):
    database = tmp_path / "db.sqlite3"
    storage.init_db(database)
    created = storage.create_launch(
        database,
        lifetime=60,
        issuer="https://lms.example.org",
        client_id="abc",
        deployment_id="1",
        subject="42",
        context_id="c",
        resource_link_id="r",
        lineitem=None,
        return_url="https://lms.example.org/course/view.php?id=1",
        job_id=1,
        unit_id=2,
    )
    assert storage.get_launch(database, created.id) == created
    assert storage.get_launch(database, "unknown") is None


def test_migration_adds_return_url_to_an_old_database(tmp_path):
    database = tmp_path / "db.sqlite3"
    with storage.connect(database) as connection:
        connection.execute(
            "CREATE TABLE launches (id TEXT PRIMARY KEY, issuer TEXT NOT NULL, client_id TEXT NOT NULL, "
            "deployment_id TEXT NOT NULL, subject TEXT NOT NULL, context_id TEXT, resource_link_id TEXT NOT NULL, "
            "lineitem TEXT, job_id INTEGER NOT NULL, unit_id INTEGER NOT NULL, created_at REAL NOT NULL, "
            "expires_at REAL NOT NULL)"
        )
    storage.init_db(database)
    with storage.connect(database) as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(launches)")}
    assert "return_url" in columns


@pytest.fixture
def app_without_keys(tmp_path, monkeypatch):
    # /lti/session does not use the tool's key pair; no key or secret is generated in these tests
    monkeypatch.setattr(keys, "ensure_key_pair", lambda data_dir: ("unused", "unused"))
    monkeypatch.setattr(keys, "ensure_token_secret", lambda data_dir: SECRET)
    return create_app(Config(base_url="http://localhost:8080", data_dir=tmp_path / "data"))


def _create_launch(app, lifetime=60):
    return storage.create_launch(
        app.extensions["lunes_lti"].config.database_path,
        lifetime=lifetime,
        issuer="https://lms.example.org",
        client_id="abc",
        deployment_id="1",
        subject="42",
        context_id="c",
        resource_link_id="r",
        lineitem=None,
        return_url="https://lms.example.org/course/view.php?id=1",
        job_id=3,
        unit_id=7,
    )


def _token(app, launch_id, lifetime=60):
    return session_token.issue(app.extensions["lunes_lti"].token_secret, launch_id, lifetime)


def test_session_returns_the_launch(app_without_keys):
    launch = _create_launch(app_without_keys)
    response = app_without_keys.test_client().get(
        "/lti/session", headers={"Authorization": f"Bearer {_token(app_without_keys, launch.id)}"}
    )
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.get_json() == {
        "jobId": 3,
        "unitId": 7,
        "returnUrl": "https://lms.example.org/course/view.php?id=1",
        "expiresAt": int(launch.expires_at),
    }


@pytest.mark.parametrize(
    ("authorization", "error"),
    [(None, "missing"), ("Basic abc", "missing"), ("Bearer not-a-token", "invalid")],
)
def test_session_rejects_missing_and_invalid_tokens(app_without_keys, authorization, error):
    headers = {"Authorization": authorization} if authorization else {}
    response = app_without_keys.test_client().get("/lti/session", headers=headers)
    assert (response.status_code, response.get_json()) == (401, {"error": error})


def test_session_reports_expiry(app_without_keys):
    expired_token = jwt.encode(
        {"iss": "lunes-lti", "lid": "x", "iat": int(time.time()) - 120, "exp": int(time.time()) - 60},
        app_without_keys.extensions["lunes_lti"].token_secret,
        algorithm="HS256",
    )
    expired_launch = _create_launch(app_without_keys, lifetime=-1)
    for token in (expired_token, _token(app_without_keys, expired_launch.id)):
        response = app_without_keys.test_client().get("/lti/session", headers={"Authorization": f"Bearer {token}"})
        assert (response.status_code, response.get_json()) == (401, {"error": "expired"})
