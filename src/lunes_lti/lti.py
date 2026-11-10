"""Adjustments of the PyLTI1p3 Flask adapter.

- Cookies: PyLTI1p3 sets ``Secure; SameSite=None`` only if Flask sees an HTTPS request. Behind nginx (TLS ends there)
  and behind the webpack dev server Flask sees HTTP, and the browser would fall back to ``SameSite=Lax`` and drop the
  state cookie on the cross-site form POST of the launch. The cookies are therefore always ``Secure; SameSite=None``
  (browsers accept ``Secure`` cookies from ``http://localhost``) and additionally ``Partitioned`` (CHIPS), so they
  keep working in the LMS iframe where browsers block unpartitioned third-party cookies.
- Data minimisation: PyLTI1p3 caches the whole launch token. Claims that identify a person are removed first.
"""

import typing as t

from pylti1p3.contrib.flask import (
    FlaskCookieService,
    FlaskMessageLaunch,
    FlaskOIDCLogin,
    FlaskRequest,
    FlaskSessionService,
)
from pylti1p3.tool_config import ToolConfDict

from .config import Config

CLAIM = "https://purl.imsglobal.org/spec/lti/claim/"
CUSTOM_CLAIM = CLAIM + "custom"
CONTEXT_CLAIM = CLAIM + "context"
DEPLOYMENT_ID_CLAIM = CLAIM + "deployment_id"
RESOURCE_LINK_CLAIM = CLAIM + "resource_link"
LAUNCH_PRESENTATION_CLAIM = CLAIM + "launch_presentation"
AGS_CLAIM = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"

# Claims that may identify a person. Moodle sends name and e-mail unless the privacy settings of the tool forbid it,
# and always its username in "ext" and the user's ID number in "lis".
PERSONAL_CLAIMS = frozenset(
    {
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "email",
        "email_verified",
        "picture",
        "profile",
        "phone_number",
        "address",
        "birthdate",
        CLAIM + "lis",
        CLAIM + "ext",
        CLAIM + "lti1p1",
    }
)

# Lifetime of nonce, state and the cached launch in the launch data storage, in seconds
LAUNCH_DATA_LIFETIME = 2 * 60 * 60


def minimise(launch_data: t.Mapping[str, t.Any]) -> dict[str, t.Any]:
    return {key: value for key, value in launch_data.items() if key not in PERSONAL_CLAIMS}


def tool_conf(config: Config, private_key: str, public_key: str) -> ToolConfDict:
    settings = {
        platform.issuer: [
            {
                # The only client of this issuer is used if the LMS sends no client_id at login
                "default": True,
                "client_id": platform.client_id,
                "auth_login_url": platform.auth_login_url,
                "auth_token_url": platform.auth_token_url,
                "key_set_url": platform.key_set_url,
                "deployment_ids": platform.deployment_ids,
            }
        ]
        for platform in config.platforms
    }
    conf = ToolConfDict(settings)
    for platform in config.platforms:
        conf.set_private_key(platform.issuer, private_key, client_id=platform.client_id)
        conf.set_public_key(platform.issuer, public_key, client_id=platform.client_id)
    return conf


def request() -> FlaskRequest:
    # Reported as secure for the cookie attributes and the cookie check page, see module docstring
    return FlaskRequest(request_is_secure=True)


class CookieService(FlaskCookieService):
    def __init__(self, lti_request, path: str):
        super().__init__(lti_request)
        self._path = path

    def update_response(self, response):
        for key, cookie_data in self._cookie_data_to_set.items():
            response.set_cookie(
                key=key,
                value=cookie_data["value"],
                max_age=cookie_data["exp"],
                path=self._path,
                secure=True,
                httponly=True,
                samesite="None",
                partitioned=True,
            )


class SessionService(FlaskSessionService):
    _launch_data_lifetime = LAUNCH_DATA_LIFETIME


class OIDCLogin(FlaskOIDCLogin):
    def __init__(self, lti_request, tool_config, launch_data_storage, cookie_path: str):
        super().__init__(
            lti_request,
            tool_config,
            session_service=SessionService(lti_request),
            cookie_service=CookieService(lti_request, cookie_path),
            launch_data_storage=launch_data_storage,
        )


class MessageLaunch(FlaskMessageLaunch):
    def __init__(self, lti_request, tool_config, launch_data_storage, cookie_path: str):
        super().__init__(
            lti_request,
            tool_config,
            session_service=SessionService(lti_request),
            cookie_service=CookieService(lti_request, cookie_path),
            launch_data_storage=launch_data_storage,
        )

    def save_launch_data(self):
        # Same as PyLTI1p3, but caches the launch without personal claims
        state = self._get_request_param("state")
        self._session_service.save_launch_data(self._launch_id, minimise(self._jwt["body"]))
        self._session_service.set_state_valid(state, self._get_id_token_hash())
        return self
