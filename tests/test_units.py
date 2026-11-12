"""Tests without key generation."""

import json
import re
import time
from datetime import datetime, timezone

import jwt
import pytest
import requests
from pylti1p3.exception import LtiServiceException

from lunes_lti import create_app, grades, keys, views
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
        ags_endpoint=None,
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


def _create_launch(app, lifetime=60, ags_endpoint=None, role="learner"):
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
        ags_endpoint=ags_endpoint,
        return_url="https://lms.example.org/course/view.php?id=1",
        job_id=3,
        unit_id=7,
        role=role,
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


AGS_ENDPOINT = json.dumps(
    {
        "scope": [grades.SCORE_SCOPE],
        "lineitem": "https://lms.example.org/mod/lti/services.php/4/lineitems/9/lineitem?type_id=1",
    }
)


def _post_result(app, token, body):
    return app.test_client().post("/lti/results", json=body, headers={"Authorization": f"Bearer {token}"})


def test_results_are_sent_to_the_gradebook(app_without_keys, monkeypatch):
    sent = []
    monkeypatch.setattr(grades, "send_result", lambda conf, key, launch, result: sent.append((launch, result)))
    launch = _create_launch(app_without_keys, ags_endpoint=AGS_ENDPOINT)

    response = _post_result(app_without_keys, _token(app_without_keys, launch.id), {"correct": 6, "total": 8})

    assert response.status_code == 204
    assert sent == [(launch, grades.ExerciseResult(correct=6, total=8))]


def test_results_carry_the_time_on_task(app_without_keys, monkeypatch):
    sent = []
    monkeypatch.setattr(grades, "send_result", lambda conf, key, launch, result: sent.append(result))
    launch = _create_launch(app_without_keys, ags_endpoint=AGS_ENDPOINT)
    body = {"correct": 6, "total": 8, "durationSeconds": 95}

    response = _post_result(app_without_keys, _token(app_without_keys, launch.id), body)

    assert response.status_code == 204
    assert sent == [grades.ExerciseResult(correct=6, total=8, duration_seconds=95)]


@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        {"correct": 9, "total": 8},
        {"correct": -1, "total": 8},
        {"correct": 0, "total": 0},
        {"correct": True, "total": 8},
        {"correct": "6", "total": 8},
        {"correct": 1, "total": 1001},
        {"correct": 1, "total": 1, "durationSeconds": -1},
        {"correct": 1, "total": 1, "durationSeconds": 86401},
        {"correct": 1, "total": 1, "durationSeconds": 9.5},
        {"correct": 1, "total": 1, "durationSeconds": "95"},
    ],
)
def test_invalid_results_are_rejected(app_without_keys, monkeypatch, body):
    monkeypatch.setattr(grades, "send_result", lambda *args: pytest.fail("must not be sent"))
    launch = _create_launch(app_without_keys, ags_endpoint=AGS_ENDPOINT)

    response = _post_result(app_without_keys, _token(app_without_keys, launch.id), body)

    assert (response.status_code, response.get_json()) == (422, {"error": "invalid_result"})


@pytest.mark.parametrize("role", ["instructor", "other"])
def test_results_of_teachers_are_a_preview(app_without_keys, monkeypatch, role):
    monkeypatch.setattr(grades, "send_result", lambda *args: pytest.fail("must not be sent"))
    launch = _create_launch(app_without_keys, ags_endpoint=AGS_ENDPOINT, role=role)

    response = _post_result(app_without_keys, _token(app_without_keys, launch.id), {"correct": 1, "total": 1})

    assert (response.status_code, response.get_json()) == (409, {"error": "preview"})


def test_results_need_a_valid_token(app_without_keys):
    response = _post_result(app_without_keys, "not-a-token", {"correct": 1, "total": 1})
    assert (response.status_code, response.get_json()) == (401, {"error": "invalid"})


@pytest.mark.parametrize(
    "ags_endpoint",
    [None, json.dumps({"scope": [grades.SCORE_SCOPE]}), json.dumps({"scope": [], "lineitem": "https://x/li"})],
)
def test_results_of_activities_without_grades(app_without_keys, ags_endpoint):
    launch = _create_launch(app_without_keys, ags_endpoint=ags_endpoint)

    response = _post_result(app_without_keys, _token(app_without_keys, launch.id), {"correct": 1, "total": 1})

    assert (response.status_code, response.get_json()) == (409, {"error": "not_graded"})


def test_rejected_grades_are_reported(app_without_keys, monkeypatch):
    error_response = requests.Response()
    error_response.status_code = 400

    def reject(*args):
        raise LtiServiceException(error_response)

    monkeypatch.setattr(grades, "send_result", reject)
    launch = _create_launch(app_without_keys, ags_endpoint=AGS_ENDPOINT)

    response = _post_result(app_without_keys, _token(app_without_keys, launch.id), {"correct": 1, "total": 1})

    assert (response.status_code, response.get_json()) == (502, {"error": "lms_error"})


def test_build_grade():
    launch = storage.Launch(
        id="l",
        issuer="i",
        client_id="c",
        deployment_id="d",
        subject="user-42",
        context_id=None,
        resource_link_id="r",
        lineitem=None,
        ags_endpoint=AGS_ENDPOINT,
        return_url=None,
        job_id=1,
        unit_id=2,
        created_at=0,
        expires_at=0,
    )
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)

    grade = json.loads(grades.build_grade(launch, grades.ExerciseResult(6, 8), now).get_value())

    assert grade == {
        "scoreGiven": 6,
        "scoreMaximum": 8,
        "activityProgress": "Completed",
        "gradingProgress": "FullyGraded",
        "timestamp": "2026-11-10T12:00:00.000+00:00",
        "userId": "user-42",
    }

    with_duration = grades.build_grade(launch, grades.ExerciseResult(6, 8, duration_seconds=95), now).get_value()
    assert json.loads(with_duration) == grade | {
        "comment": "Bearbeitungszeit: 1 min 35 s",
        "submission": {"startedAt": "2026-11-10T11:58:25.000+00:00", "submittedAt": "2026-11-10T12:00:00.000+00:00"},
    }


@pytest.mark.parametrize(
    ("seconds", "text"), [(0, "0 s"), (42, "42 s"), (60, "1 min 0 s"), (192, "3 min 12 s"), (3900, "1 h 5 min 0 s")]
)
def test_format_duration(seconds, text):
    assert grades.format_duration(seconds) == text


def _error_response(status, url, text):
    response = requests.Response()
    response.status_code = status
    response.url = url
    response._content = text.encode("utf-8")
    response.encoding = "utf-8"
    return response


def test_lms_errors_are_logged_briefly():
    page = (
        '<html><script>var M = {"sesskey":"secret-session-key"};</script>'
        '<p class="errormessage">Fehler: fix_jwks_alg(): Argument #1 ($jwks) must be of type array</p></html>'
    )
    description = views.describe_lms_error(
        _error_response(404, "https://lms.example.org/mod/lti/token.php?x=1", page)
    )
    assert description == (
        "404 https://lms.example.org/mod/lti/token.php: "
        "Fehler: fix_jwks_alg(): Argument #1 ($jwks) must be of type array"
    )
    assert "secret-session-key" not in description

    json_error = views.describe_lms_error(
        _error_response(400, "https://lms.example.org/token", '{"error": "invalid_client", "reason": "bad kid"}')
    )
    assert json_error == "400 https://lms.example.org/token: invalid_client bad kid"


# Deep Linking (vocabulary set picker)

from lunes_lti import cms, deep_linking  # noqa: E402

CMS_URL = "https://cms.example.org/api/v2"

CONTEXT = deep_linking.Context(
    issuer="https://lms.example.org",
    client_id="abc",
    deployment_id="1",
    return_url="https://lms.example.org/mod/lti/contentitem_return.php",
    data='{"id":"42"}',
)
JOBS = [cms.Job(3, "Bäcker:in"), cms.Job(5, "Pflege")]
UNITS = {3: [cms.Unit(7, "Organe", 6), cms.Unit(8, "Backformen", 1)], 5: []}


def test_picker_token_round_trip_and_separation_from_session_tokens():
    token = deep_linking.issue(SECRET, CONTEXT)
    assert deep_linking.verify(SECRET, token) == CONTEXT
    with pytest.raises(jwt.InvalidTokenError):
        deep_linking.verify(SECRET, session_token.issue(SECRET, "launch-1", 60))
    with pytest.raises(jwt.InvalidTokenError):
        session_token.verify(SECRET, token)
    with pytest.raises(jwt.ExpiredSignatureError):
        deep_linking.verify(SECRET, deep_linking.issue(SECRET, CONTEXT, lifetime=-1))


def test_resource_link_carries_the_set_and_a_line_item():
    resource = deep_linking.resource_link("http://localhost:8080/lti/launch", 3, 7, "Organe").to_dict()
    assert resource["type"] == "ltiResourceLink"
    assert resource["url"] == "http://localhost:8080/lti/launch"
    assert resource["title"] == "Organe"
    assert resource["custom"] == {"job_id": "3", "unit_id": "7"}
    assert resource["lineItem"] == {"scoreMaximum": 100, "label": "Organe"}


def test_cms_lists(monkeypatch):
    responses = {
        "https://cms.example.org/api/v2/jobs": [
            {"id": 5, "name": "pflege"},
            {"id": 3, "name": "Bäcker:in"},
            {"name": "ohne ID"},
        ],
        "https://cms.example.org/api/v2/jobs/3/units": [{"id": 7, "title": "Organe", "number_words": 6}],
    }
    monkeypatch.setattr(cms, "_get", lambda url, timeout=cms.TIMEOUT: responses[url])
    assert cms.list_jobs("https://cms.example.org/api/v2") == [cms.Job(3, "Bäcker:in"), cms.Job(5, "pflege")]
    assert cms.list_units("https://cms.example.org/api/v2", 3) == [cms.Unit(7, "Organe", 6)]


def test_cms_rejects_unexpected_answers(monkeypatch):
    with pytest.raises(cms.CmsError):
        cms._get("file:///etc/passwd")
    monkeypatch.setattr(cms, "_get", lambda url: {"detail": "not found"})
    with pytest.raises(cms.CmsError):
        cms.list_jobs("https://cms.example.org/api/v2")


@pytest.fixture
def picker_app(tmp_path, monkeypatch):
    monkeypatch.setattr(keys, "ensure_key_pair", lambda data_dir: ("unused", "unused"))
    monkeypatch.setattr(keys, "ensure_token_secret", lambda data_dir: SECRET)
    monkeypatch.setattr(cms, "list_jobs", lambda cms_url: JOBS)
    monkeypatch.setattr(cms, "list_units", lambda cms_url, job_id: UNITS[job_id])
    monkeypatch.setattr(deep_linking, "response_jwt", lambda tool_conf, public_key, context, resources: "signed-jwt")
    return create_app(
        Config(base_url="http://localhost:8080", data_dir=tmp_path / "data", cms_url="https://cms.example.org/api/v2")
    )


def _pick(app, **form):
    return app.test_client().post("/lti/deep-link", data={"token": deep_linking.issue(SECRET, CONTEXT)} | form)


def test_picker_lists_jobs_then_units(picker_app):
    page = _pick(picker_app).get_data(as_text=True)
    assert "Bäcker:in" in page and "Pflege" in page
    assert "Organe" not in page

    page = _pick(picker_app, job_id="3").get_data(as_text=True)
    assert "Organe" in page and "6 Wörter" in page and "1 Wort<" in page
    assert 'action="deep-link"' in page

    assert "noch keine Vokabelsets" in _pick(picker_app, job_id="5").get_data(as_text=True)


def test_picker_sends_the_chosen_set_back_to_the_lms(picker_app, monkeypatch):
    sent = {}

    def response_jwt(tool_conf, public_key, context, resources):
        sent.update(context=context, resources=[resource.to_dict() for resource in resources])
        return "signed-jwt"

    monkeypatch.setattr(deep_linking, "response_jwt", response_jwt)
    response = _pick(picker_app, job_id="3", unit_id="7")

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert f'action="{CONTEXT.return_url}"' in page
    assert 'name="JWT" value="signed-jwt"' in page
    assert sent["context"] == CONTEXT
    assert sent["resources"][0]["custom"] == {"job_id": "3", "unit_id": "7"}
    assert sent["resources"][0]["url"] == "http://localhost:8080/lti/launch"


def test_picker_ignores_a_set_of_another_job(picker_app):
    page = _pick(picker_app, job_id="3", unit_id="99").get_data(as_text=True)
    assert "signed-jwt" not in page
    assert "Organe" in page


def test_picker_needs_a_valid_token(picker_app):
    response = picker_app.test_client().post("/lti/deep-link", data={"token": "forged", "job_id": "3"})
    assert response.status_code == 400
    session = session_token.issue(SECRET, "launch-1", 60)
    assert picker_app.test_client().post("/lti/deep-link", data={"token": session}).status_code == 400


def test_picker_reports_missing_configuration_and_cms_errors(picker_app, app_without_keys, monkeypatch):
    response = app_without_keys.test_client().post(
        "/lti/deep-link", data={"token": deep_linking.issue(SECRET, CONTEXT)}
    )
    assert response.status_code == 500

    def fail(cms_url):
        raise cms.CmsError("down")

    monkeypatch.setattr(cms, "list_jobs", fail)
    assert _pick(picker_app).status_code == 502


def test_load_config_reads_the_cms_url(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text('base_url = "http://localhost:8080"\ncms_url = "https://cms.example.org/api/v2/"\n')
    assert load_config(config_file).cms_url == "https://cms.example.org/api/v2"
    config_file.write_text('base_url = "http://localhost:8080"\n')
    assert load_config(config_file).cms_url is None


def test_cms_tells_withdrawn_professions_from_errors(monkeypatch):
    import urllib.error

    def answer(status):
        def urlopen(request, timeout):
            raise urllib.error.HTTPError(request.full_url, status, "error", {}, None)

        return urlopen

    monkeypatch.setattr(cms.urllib.request, "urlopen", answer(403))
    with pytest.raises(cms.NotFound):
        cms._get("https://cms.example.org/api/v2/jobs/9/units")
    monkeypatch.setattr(cms.urllib.request, "urlopen", answer(500))
    with pytest.raises(cms.CmsError) as error:
        cms._get("https://cms.example.org/api/v2/jobs/9/units")
    assert not isinstance(error.value, cms.NotFound)


def test_find_unit(monkeypatch):
    def list_units(cms_url, job_id, timeout):
        if job_id == 9:
            raise cms.NotFound("withdrawn")
        return [cms.Unit(7, "Organe", 6)]

    monkeypatch.setattr(cms, "list_units", list_units)
    assert cms.find_unit(CMS_URL, 3, 7) == cms.Unit(7, "Organe", 6)
    assert cms.find_unit(CMS_URL, 3, 8) is None
    assert cms.find_unit(CMS_URL, 9, 7) is None


@pytest.fixture
def app_with_cms(tmp_path, monkeypatch):
    monkeypatch.setattr(keys, "ensure_key_pair", lambda data_dir: ("unused", "unused"))
    monkeypatch.setattr(keys, "ensure_token_secret", lambda data_dir: SECRET)
    return create_app(Config(base_url="http://localhost:8080", data_dir=tmp_path / "data", cms_url=CMS_URL))


def test_launch_check_blocks_only_withdrawn_sets(app_with_cms, app_without_keys, monkeypatch):
    answers = {7: cms.Unit(7, "Organe", 6), 8: None}

    def find_unit(cms_url, job_id, unit_id, timeout):
        assert timeout == views.LAUNCH_CMS_TIMEOUT
        if unit_id == 9:
            raise cms.CmsError("timeout")
        return answers[unit_id]

    monkeypatch.setattr(cms, "find_unit", find_unit)
    with app_with_cms.app_context():
        assert views._is_unit_available(3, 7) is True
        assert views._is_unit_available(3, 8) is False
        # The CMS cannot answer: the launch goes ahead
        assert views._is_unit_available(3, 9) is True
    with app_without_keys.app_context():
        # Without cms_url there is nothing to check
        assert views._is_unit_available(3, 8) is True


MEMBERSHIP = "http://purl.imsglobal.org/vocab/lis/v2/membership"


@pytest.mark.parametrize(
    ("roles", "role"),
    [
        ([f"{MEMBERSHIP}#Learner"], "learner"),
        (["Learner"], "learner"),
        ([f"{MEMBERSHIP}#Instructor"], "instructor"),
        ([f"{MEMBERSHIP}/Instructor#TeachingAssistant"], "instructor"),
        # Teacher who is also enrolled as a learner: preview, never a grade
        ([f"{MEMBERSHIP}#Learner", f"{MEMBERSHIP}#Instructor"], "instructor"),
        # Site administrator without a role in the course
        (["http://purl.imsglobal.org/vocab/lis/v2/institution/person#Administrator"], "other"),
        ([f"{MEMBERSHIP}#Mentor"], "other"),
        ([], "other"),
        (None, "other"),
        ("Learner", "other"),
    ],
)
def test_course_role(roles, role):
    assert lti.course_role(roles) == role


def test_launches_stored_before_the_role_count_as_learners(tmp_path):
    database = tmp_path / "lti.sqlite"
    old_schema = re.sub(r",\s*-- Role.*\n\s*role TEXT.*", "", storage.SCHEMA)
    assert "role TEXT" not in old_schema
    with storage.connect(database) as connection:
        connection.executescript(old_schema)
        connection.execute(
            "INSERT INTO launches (id, issuer, client_id, deployment_id, subject, resource_link_id, job_id, unit_id,"
            " created_at, expires_at) VALUES ('old', 'i', 'c', 'd', 's', 'r', 1, 2, ?, ?)",
            (time.time(), time.time() + 60),
        )
    connection.close()

    storage.init_db(database)

    assert storage.get_launch(database, "old").role == "learner"


def test_launch_data_storage_removes_values(tmp_path):
    database = tmp_path / "lti.sqlite"
    storage.init_db(database)
    launch_data = storage.SqliteLaunchDataStorage(database)
    launch_data.set_value("nonce-abc", True, exp=60)

    launch_data.remove_value("nonce-abc")

    assert launch_data.check_value("nonce-abc") is False

