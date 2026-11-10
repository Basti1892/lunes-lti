"""End-to-end tests of login, launch and JWKS against a simulated LMS.

These tests generate throwaway RSA keys (tool and simulated LMS) in a temporary directory, marked ``keys``.
"""

import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from jwcrypto.jwk import JWK

from lunes_lti import create_app, lti, session_token, storage
from lunes_lti.config import Config, Platform

pytestmark = pytest.mark.keys

ISSUER = "https://lms.example.org"
CLIENT_ID = "client-1"
DEPLOYMENT_ID = "deployment-1"
TOOL_URL = "https://tool.example.org"
HTTPS = "https://localhost"


@pytest.fixture(scope="module")
def platform_key():
    return JWK.generate(kty="RSA", size=2048, kid="platform-key")


@pytest.fixture
def app(tmp_path, platform_key, monkeypatch):
    public_jwk = json.loads(platform_key.export_public()) | {"alg": "RS256"}
    monkeypatch.setattr(lti.MessageLaunch, "fetch_public_key", lambda self, url: {"keys": [public_jwk]})
    config = Config(
        base_url=TOOL_URL,
        data_dir=tmp_path / "data",
        platforms=[
            Platform(
                issuer=ISSUER,
                client_id=CLIENT_ID,
                auth_login_url=f"{ISSUER}/auth",
                auth_token_url=f"{ISSUER}/token",
                key_set_url=f"{ISSUER}/certs",
                deployment_ids=[DEPLOYMENT_ID],
            )
        ],
    )
    return create_app(config)


LOGIN_PARAMS = {
    "iss": ISSUER,
    "login_hint": "hint",
    "target_link_uri": f"{TOOL_URL}/lti/launch",
    "client_id": CLIENT_ID,
    "lti_message_hint": "message-hint",
}


def login(client, **extra):
    return client.post("/lti/login", data=LOGIN_PARAMS | {"lti1p3_new_window": "1"} | extra, base_url=HTTPS)


def id_token(platform_key, nonce, custom=None):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-42",
        "iat": now,
        "exp": now + 60,
        "nonce": nonce,
        "name": "Ada Lovelace",
        "email": "ada@example.org",
        lti.CLAIM + "ext": {"user_username": "ada.l"},
        lti.CLAIM + "message_type": "LtiResourceLinkRequest",
        lti.CLAIM + "version": "1.3.0",
        lti.DEPLOYMENT_ID_CLAIM: DEPLOYMENT_ID,
        lti.CLAIM + "roles": ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        lti.CLAIM + "target_link_uri": f"{TOOL_URL}/lti/launch",
        lti.RESOURCE_LINK_CLAIM: {"id": "resource-1"},
        lti.CONTEXT_CLAIM: {"id": "course-1", "title": "Kurs"},
        lti.AGS_CLAIM: {"lineitem": f"{ISSUER}/lineitems/1"},
        lti.CUSTOM_CLAIM: {"job_id": "3", "unit_id": "7"} if custom is None else custom,
    }
    private_pem = platform_key.export_to_pem(private_key=True, password=None)
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": "platform-key"})


def test_jwks_publishes_only_the_public_key(app):
    keys = app.test_client().get("/lti/jwks").get_json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kty"] == "RSA" and keys[0]["alg"] == "RS256" and keys[0]["use"] == "sig"
    assert "d" not in keys[0]


def test_login_shows_cookie_check_first(app):
    response = app.test_client().post("/lti/login", data=LOGIN_PARAMS, base_url=HTTPS)
    assert response.status_code == 200
    assert "lti1p3_test_cookie" in response.get_data(as_text=True)


def test_login_redirects_to_the_platform_with_iframe_compatible_cookies(app):
    response = login(app.test_client())
    assert response.status_code == 302
    location = urlparse(response.location)
    assert f"{location.scheme}://{location.netloc}{location.path}" == f"{ISSUER}/auth"
    query = parse_qs(location.query)
    assert query["redirect_uri"] == [f"{TOOL_URL}/lti/launch"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["lti_message_hint"] == ["message-hint"]

    cookies = response.headers.getlist("Set-Cookie")
    assert {cookie.split("=")[0] for cookie in cookies} == {"lti1p3-session-id", f"lti1p3-{query['state'][0]}"}
    for cookie in cookies:
        for attribute in ("Secure", "HttpOnly", "SameSite=None", "Partitioned", "Path=/lti/"):
            assert attribute in cookie


def test_launch_redirects_into_the_app_and_stores_no_personal_data(app, platform_key):
    client = app.test_client()
    query = parse_qs(urlparse(login(client).location).query)

    response = client.post(
        "/lti/launch",
        data={"id_token": id_token(platform_key, query["nonce"][0]), "state": query["state"][0]},
        base_url=HTTPS,
    )

    assert response.status_code == 302
    prefix = f"{TOOL_URL}/jobs/3/units/7#lti_token="
    assert response.location.startswith(prefix)
    state = app.extensions["lunes_lti"]
    launch_id = session_token.verify(state.token_secret, response.location[len(prefix) :])
    launch = storage.get_launch(state.config.database_path, launch_id)
    assert (launch.subject, launch.context_id, launch.resource_link_id) == ("user-42", "course-1", "resource-1")
    assert launch.lineitem == f"{ISSUER}/lineitems/1"
    assert (launch.job_id, launch.unit_id) == (3, 7)

    database = state.config.database_path.read_bytes()
    for personal in (b"Ada Lovelace", b"ada@example.org", b"ada.l"):
        assert personal not in database


def test_launch_without_login_cookies_is_rejected(app, platform_key):
    query = parse_qs(urlparse(login(app.test_client()).location).query)
    response = app.test_client().post(
        "/lti/launch",
        data={"id_token": id_token(platform_key, query["nonce"][0]), "state": query["state"][0]},
        base_url=HTTPS,
    )
    assert response.status_code == 400


def test_launch_without_vocabulary_set_is_rejected(app, platform_key):
    client = app.test_client()
    query = parse_qs(urlparse(login(client).location).query)
    response = client.post(
        "/lti/launch",
        data={"id_token": id_token(platform_key, query["nonce"][0], custom={}), "state": query["state"][0]},
        base_url=HTTPS,
    )
    assert response.status_code == 422
