"""LTI endpoints: OIDC login initiation, launch, Deep Linking picker, session, results, JWKS."""

import html
import json
import logging
import re
from urllib.parse import quote, urlparse

import jwt
from flask import Blueprint, current_app, jsonify, redirect, render_template, request
from pylti1p3.exception import LtiException, LtiServiceException, OIDCException

from . import cms, deep_linking, grades, lti, session_token, storage

logger = logging.getLogger(__name__)

bp = Blueprint("lti", __name__, url_prefix="/lti")

COOKIE_CHECK_TEXTS = {
    "main_msg": "Dein Browser erlaubt keine Cookies in eingebetteten Inhalten.",
    "click_msg": "Lunes in einem neuen Tab öffnen.",
    "loading_msg": "Lunes wird geladen …",
}


def _state():
    return current_app.extensions["lunes_lti"]


def _launch_data_storage():
    return storage.SqliteLaunchDataStorage(_state().config.database_path)


def _error(message: str, status: int = 400):
    return render_template("error.html", message=message), status


@bp.route("/login", methods=["GET", "POST"])
def login():
    """OIDC login initiation (third-party initiated login), called by the LMS."""
    lti_request = lti.request()
    try:
        oidc_login = lti.OIDCLogin(
            lti_request, _state().tool_conf, _launch_data_storage(), _state().config.cookie_path
        )
        # The cookie check page opens the login in a new tab if the browser blocks cookies in the iframe
        return oidc_login.enable_check_cookies(**COOKIE_CHECK_TEXTS).redirect(_state().config.launch_url)
    except (LtiException, OIDCException) as error:
        logger.warning("LTI login failed: %s", error)
        return _error("Der Start aus der Lernplattform ist fehlgeschlagen.")


def _http_url(value) -> str | None:
    return value if isinstance(value, str) and urlparse(value).scheme in ("http", "https") else None


def _positive_int(value) -> int | None:
    text = str(value).strip() if value is not None else ""
    return int(text) if text.isdigit() and int(text) > 0 else None


@bp.post("/launch")
def launch():
    """Launch (redirect URI of the OIDC login): validates the id_token and redirects into the app."""
    state = _state()
    lti_request = lti.request()
    try:
        message_launch = lti.MessageLaunch(
            lti_request, state.tool_conf, _launch_data_storage(), state.config.cookie_path
        )
        launch_data = message_launch.get_launch_data()
    except LtiException as error:
        # Missing cookies end up here as well ("Missing state param", "Missing ... cookie", "State not found")
        logger.warning("LTI launch failed: %s", error)
        return _error("Der Start aus der Lernplattform ist fehlgeschlagen. Bitte starte die Aktivität erneut.")

    if message_launch.is_deep_link_launch():
        return _start_deep_linking(message_launch, launch_data)
    if not message_launch.is_resource_launch():
        return _error("Diese Art von Start wird noch nicht unterstützt.")

    # The vocabulary set comes from the custom parameters of the activity, set by Deep Linking (or by hand)
    custom = launch_data.get(lti.CUSTOM_CLAIM) or {}
    job_id = _positive_int(custom.get("job_id"))
    unit_id = _positive_int(custom.get("unit_id"))
    if job_id is None or unit_id is None:
        logger.warning("LTI launch without valid job_id/unit_id custom parameters")
        return _error(
            "In der Aktivität ist kein Vokabelset eingestellt (Parameter job_id und unit_id fehlen).", status=422
        )

    created = storage.create_launch(
        state.config.database_path,
        lifetime=state.config.token_lifetime,
        issuer=launch_data["iss"],
        client_id=message_launch.get_client_id(),
        deployment_id=launch_data[lti.DEPLOYMENT_ID_CLAIM],
        subject=launch_data["sub"],
        context_id=(launch_data.get(lti.CONTEXT_CLAIM) or {}).get("id"),
        resource_link_id=launch_data[lti.RESOURCE_LINK_CLAIM]["id"],
        lineitem=(launch_data.get(lti.AGS_CLAIM) or {}).get("lineitem"),
        ags_endpoint=json.dumps(launch_data[lti.AGS_CLAIM]) if lti.AGS_CLAIM in launch_data else None,
        return_url=_http_url((launch_data.get(lti.LAUNCH_PRESENTATION_CLAIM) or {}).get("return_url")),
        job_id=job_id,
        unit_id=unit_id,
    )
    token = session_token.issue(state.token_secret, created.id, state.config.token_lifetime)

    # The token goes into the fragment: browsers do not send it to servers, so it does not end up in access logs
    return redirect(f"{state.config.base_url}/jobs/{job_id}/units/{unit_id}#lti_token={quote(token)}")


def _start_deep_linking(message_launch, launch_data):
    settings = launch_data.get(deep_linking.SETTINGS_CLAIM) or {}
    return_url = _http_url(settings.get("deep_link_return_url"))
    if return_url is None or deep_linking.RESOURCE_LINK_TYPE not in (settings.get("accept_types") or []):
        logger.warning("Deep Linking request without return URL or without accepting LTI resource links")
        return _error("Die Lernplattform erwartet einen Inhalt, den Lunes nicht anbietet.", status=422)
    context = deep_linking.Context(
        issuer=launch_data["iss"],
        client_id=message_launch.get_client_id(),
        deployment_id=launch_data[lti.DEPLOYMENT_ID_CLAIM],
        return_url=return_url,
        data=settings.get("data"),
    )
    return _picker(deep_linking.issue(_state().token_secret, context), job_id=None, unit_id=None)


@bp.post("/deep-link")
def deep_link():
    """Steps of the vocabulary set picker: profession, then set. The chosen set goes back to the LMS."""
    token = request.form.get("token", "")
    try:
        deep_linking.verify(_state().token_secret, token)
    except jwt.InvalidTokenError:
        return _error("Die Auswahl ist abgelaufen. Bitte öffne die Auswahl in der Lernplattform erneut.")
    return _picker(
        token, job_id=_positive_int(request.form.get("job_id")), unit_id=_positive_int(request.form.get("unit_id"))
    )


def _picker(token: str, job_id: int | None, unit_id: int | None):
    state = _state()
    if state.config.cms_url is None:
        logger.warning("Deep Linking needs cms_url in the configuration")
        return _error("Die Auswahl der Vokabelsets ist nicht eingerichtet (cms_url fehlt).", status=500)
    try:
        jobs = cms.list_jobs(state.config.cms_url)
        job = next((job for job in jobs if job.id == job_id), None)
        units = cms.list_units(state.config.cms_url, job.id) if job is not None else []
    except cms.CmsError as error:
        logger.warning("Vocabulary sets could not be loaded: %s", error)
        return _error("Die Vokabelsets konnten gerade nicht geladen werden. Bitte versuche es später noch einmal.", 502)

    unit = next((unit for unit in units if unit.id == unit_id), None)
    if job is None or unit is None:
        return render_template("picker.html", token=token, jobs=jobs, job=job, units=units)

    context = deep_linking.verify(state.token_secret, token)
    resource = deep_linking.resource_link(state.config.launch_url, job.id, unit.id, unit.title)
    response_jwt = deep_linking.response_jwt(state.tool_conf, state.public_key, context, [resource])
    return render_template("deep_link_response.html", return_url=context.return_url, jwt=response_jwt, unit=unit)


@bp.get("/session")
def session():
    """Launch the app belongs to, for the session token in ``Authorization: Bearer <token>``.

    401 with ``{"error": "expired"}`` tells the app that the activity has to be started again from the LMS (FR-11).
    """
    launch, error = _launch_from_token()
    if launch is None:
        return _json_error(error, 401)

    response = jsonify(
        jobId=launch.job_id,
        unitId=launch.unit_id,
        returnUrl=launch.return_url,
        expiresAt=int(launch.expires_at),
    )
    response.headers["Cache-Control"] = "no-store"
    return response


MAX_WORDS = 1000
# One day; an attempt cannot take longer than the session token is valid anyway
MAX_DURATION_SECONDS = 24 * 60 * 60


@bp.post("/results")
def results():
    """Result of a finished exercise, sent by the app: ``{"correct": <int>, "total": <int>}`` (FR-03, FR-12), optionally
    with ``"durationSeconds": <int>``, the time on task of the attempt (FR-16).

    Answers 204 when the LMS accepted the grade, 401 like ``/lti/session``, 409 ``not_graded`` if the activity does
    not accept grades, 422 for an invalid result and 502 ``lms_error`` if the LMS rejected the grade.
    """
    launch, error = _launch_from_token()
    if launch is None:
        return _json_error(error, 401)

    body = request.get_json(silent=True)
    correct = body.get("correct") if isinstance(body, dict) else None
    total = body.get("total") if isinstance(body, dict) else None
    duration = body.get("durationSeconds") if isinstance(body, dict) else None
    is_valid = (
        all(_is_int(value) for value in (correct, total))
        and 0 < total <= MAX_WORDS
        and 0 <= correct <= total
        and (duration is None or (_is_int(duration) and 0 <= duration <= MAX_DURATION_SECONDS))
    )
    if not is_valid:
        return _json_error("invalid_result", 422)

    state = _state()
    try:
        grades.send_result(state.tool_conf, state.public_key, launch, grades.ExerciseResult(correct, total, duration))
    except grades.GradesNotAccepted:
        return _json_error("not_graded", 409)
    except LtiServiceException as error:
        logger.warning("LMS rejected the grade: %s", describe_lms_error(error.response))
        return _json_error("lms_error", 502)
    return "", 204


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


MAX_ERROR_LENGTH = 300


def describe_lms_error(response) -> str:
    """Short description of an error response of the LMS for the log.

    Not the whole response: error pages of Moodle are long HTML pages that contain a session key.
    """
    url = urlparse(response.url)
    text = response.text or ""
    detail = ""
    try:
        body = json.loads(text)
        if isinstance(body, dict):
            detail = " ".join(str(body[key]) for key in ("error", "error_description", "reason") if key in body)
    except ValueError:
        # Moodle's error page shows the message in <p class="errormessage">
        match = re.search(r'<p class="errormessage">(.*?)</p>', text, re.DOTALL)
        detail = html.unescape(re.sub(r"<[^>]+>", "", match.group(1))).strip() if match else ""
    return f"{response.status_code} {url.scheme}://{url.netloc}{url.path}: {detail[:MAX_ERROR_LENGTH]}"


def _launch_from_token() -> tuple[storage.Launch | None, str]:
    """Launch of the session token in ``Authorization: Bearer <token>``, or ``None`` with the reason."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None, "missing"
    try:
        launch_id = session_token.verify(_state().token_secret, token)
    except jwt.ExpiredSignatureError:
        return None, "expired"
    except jwt.InvalidTokenError:
        return None, "invalid"
    launch = storage.get_launch(_state().config.database_path, launch_id)
    return (launch, "") if launch is not None else (None, "expired")


def _json_error(error: str, status: int):
    response = jsonify(error=error)
    response.headers["Cache-Control"] = "no-store"
    return response, status


@bp.get("/jwks")
def jwks():
    """Public key set of the tool."""
    return {"keys": [grades.public_jwk(_state().public_key)]}
