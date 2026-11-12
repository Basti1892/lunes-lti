"""Deep Linking: the teacher picks a vocabulary set in the LMS (ADR 0017 in lunes-app).

The LMS sends an ``LtiDeepLinkingRequest`` to the launch URL. lunes-lti shows a picker and answers with a signed
``LtiDeepLinkingResponse`` that contains one LTI resource link: the launch URL with the job and unit as custom
parameters (the ones a launch reads) and a line item, so the LMS sets up the grade item.

Between the request and the answer, the picker keeps its state in a short-lived token signed with the token secret
(issuer, client, deployment, return URL and the opaque ``data`` of the LMS; nothing about the teacher). It needs no
cookies, so it also works in the iframe of the LMS dialog.
"""

import time
import typing as t
from dataclasses import asdict, dataclass

import jwt
from pylti1p3.deep_link import DeepLink
from pylti1p3.deep_link_resource import DeepLinkResource
from pylti1p3.lineitem import LineItem
from pylti1p3.tool_config import ToolConfDict

from . import grades, session_token

SETTINGS_CLAIM = "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings"
RESOURCE_LINK_TYPE = "ltiResourceLink"
AUDIENCE = "lunes-lti-deep-linking"
# Time the teacher has to pick a set, in seconds
PICKER_LIFETIME = 60 * 60
# Moodle scales the score (words correct on the first try out of all words) to the maximum grade
SCORE_MAXIMUM = 100


@dataclass(frozen=True)
class Context:
    issuer: str
    client_id: str
    deployment_id: str
    return_url: str
    # Opaque value of the LMS, sent back unchanged
    data: t.Any = None


def issue(secret: bytes, context: Context, lifetime: int = PICKER_LIFETIME) -> str:
    now = int(time.time())
    claims = {"iss": session_token.ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + lifetime, "ctx": asdict(context)}
    return jwt.encode(claims, secret, algorithm=session_token.ALGORITHM)


def verify(secret: bytes, token: str) -> Context:
    """Returns the context of a valid picker token. Raises ``jwt.InvalidTokenError`` otherwise (also when expired).

    The audience keeps session tokens and picker tokens apart in both directions.
    """
    claims = jwt.decode(
        token,
        secret,
        algorithms=[session_token.ALGORITHM],
        issuer=session_token.ISSUER,
        audience=AUDIENCE,
        options={"require": ["exp", "iat", "aud", "ctx"]},
    )
    return Context(**claims["ctx"])


def resource_link(launch_url: str, job_id: int, unit_id: int, title: str) -> DeepLinkResource:
    line_item = LineItem().set_score_maximum(SCORE_MAXIMUM).set_label(title)
    return (
        DeepLinkResource()
        .set_url(launch_url)
        .set_title(title)
        .set_custom_params({"job_id": str(job_id), "unit_id": str(unit_id)})
        .set_lineitem(line_item)
    )


class KeyIdDeepLink(DeepLink):
    """Signs the response with the key ID of the JWKS, like ``grades.KeyIdServiceConnector``.

    PyLTI1p3 only sends a ``kid`` if the PEM carries one, which a PEM never does. An LMS that fetches the key set by URL
    needs it to find the key.
    """

    def __init__(self, registration, deployment_id, deep_link_settings, key_id: str):
        super().__init__(registration, deployment_id, deep_link_settings)
        self._key_id = key_id

    def encode_jwt(self, message):
        return jwt.encode(
            message,
            self._registration.get_tool_private_key(),
            algorithm="RS256",
            headers={"kid": self._key_id},
        )


def response_jwt(tool_conf: ToolConfDict, public_key: str, context: Context, resources: list[DeepLinkResource]) -> str:
    registration = tool_conf.find_registration_by_params(context.issuer, context.client_id)
    deep_link = KeyIdDeepLink(
        registration,
        context.deployment_id,
        {"deep_link_return_url": context.return_url, "data": context.data},
        key_id=grades.key_id(public_key),
    )
    return deep_link.get_response_jwt(resources)
