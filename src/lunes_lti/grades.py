"""Grade passback to the LMS with LTI Assignment and Grade Services (AGS).

The grade of a finished word choice exercise is the number of words answered correctly on the first try out of all
words of the exercise, the same "X von Y Wörter richtig" the learner sees. Every finished attempt is sent; the LMS
keeps the latest (docs/web/0016-grade-passback.md in lunes-app).

The time on task of the attempt (docs/web/0018-time-on-task.md) goes into the standard ``submission`` field of the
score (start and end) and into the comment, which Moodle shows as feedback in the gradebook.
"""

import json
import typing as t
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from jwcrypto.jwk import JWK
from pylti1p3.assignments_grades import AssignmentsGradesService
from pylti1p3.grade import Grade
from pylti1p3.registration import Registration
from pylti1p3.service_connector import ServiceConnector
from pylti1p3.tool_config import ToolConfDict

from .storage import Launch

SCORE_SCOPE = "https://purl.imsglobal.org/spec/lti-ags/scope/score"


def key_id(public_key: str) -> str:
    """Key ID of the tool's key: its RFC 7638 thumbprint, stable as long as the key pair stays the same."""
    return JWK.from_pem(public_key.encode("utf-8")).thumbprint()


def public_jwk(public_key: str) -> dict[str, t.Any]:
    return dict(Registration.get_jwk(public_key)) | {"kid": key_id(public_key)}


class KeyIdServiceConnector(ServiceConnector):
    """Signs the token request with the key ID of the JWKS, so an LMS that fetches the JWKS finds the key.

    PyLTI1p3 only sends a ``kid`` if the PEM carries one, which a PEM never does.
    """

    def __init__(self, registration: Registration, kid: str, **kwargs: t.Any) -> None:
        super().__init__(registration, **kwargs)
        self._kid = kid

    def encode_jwt(self, message, private_key, headers):
        return super().encode_jwt(message, private_key, {**headers, "kid": self._kid})


@dataclass(frozen=True)
class ExerciseResult:
    correct: int
    total: int
    # Time from opening the exercise to finishing it, measured by the app
    duration_seconds: int | None = None


class GradesNotAccepted(Exception):
    """The launch has no AGS endpoint with the score scope or no line item: the LMS does not accept grades."""


def ags_service_data(launch: Launch) -> dict[str, t.Any]:
    endpoint = json.loads(launch.ags_endpoint) if launch.ags_endpoint else {}
    if SCORE_SCOPE not in endpoint.get("scope", []) or not endpoint.get("lineitem"):
        raise GradesNotAccepted()
    return endpoint


def format_duration(seconds: int) -> str:
    """German, short: ``42 s``, ``3 min 12 s``, ``1 h 5 min 0 s``."""
    hours, rest = divmod(seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours} h {minutes} min {seconds} s"
    return f"{minutes} min {seconds} s" if minutes else f"{seconds} s"


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds")


def build_grade(launch: Launch, result: ExerciseResult, now: datetime | None = None) -> Grade:
    finished = now or datetime.now(timezone.utc)
    grade = (
        Grade()
        .set_score_given(result.correct)
        .set_score_maximum(result.total)
        .set_activity_progress("Completed")
        .set_grading_progress("FullyGraded")
        .set_timestamp(_iso(finished))
        .set_user_id(launch.subject)
    )
    if result.duration_seconds is not None:
        started = finished - timedelta(seconds=result.duration_seconds)
        grade.set_comment(f"Bearbeitungszeit: {format_duration(result.duration_seconds)}")
        grade.set_extra_claims({"submission": {"startedAt": _iso(started), "submittedAt": _iso(finished)}})
    return grade


def send_result(tool_conf: ToolConfDict, public_key: str, launch: Launch, result: ExerciseResult) -> None:
    """Sends the result to the gradebook. Raises ``GradesNotAccepted`` or PyLTI1p3's ``LtiServiceException``."""
    service_data = ags_service_data(launch)
    registration = tool_conf.find_registration_by_params(launch.issuer, launch.client_id)
    connector = KeyIdServiceConnector(registration, key_id(public_key))
    AssignmentsGradesService(connector, service_data).put_grade(build_grade(launch, result))
