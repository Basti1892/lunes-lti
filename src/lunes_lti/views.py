"""LTI endpoints: OIDC login initiation, launch, JWKS."""

import logging
from urllib.parse import quote

from flask import Blueprint, current_app, redirect, render_template
from pylti1p3.exception import LtiException, OIDCException
from pylti1p3.registration import Registration

from . import lti, session_token, storage

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

    if not message_launch.is_resource_launch():
        return _error("Diese Art von Start wird noch nicht unterstützt.")

    # Until Deep Linking exists, the vocabulary set comes from the custom parameters of the activity
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
        job_id=job_id,
        unit_id=unit_id,
    )
    token = session_token.issue(state.token_secret, created.id, state.config.token_lifetime)

    # The token goes into the fragment: browsers do not send it to servers, so it does not end up in access logs
    return redirect(f"{state.config.base_url}/jobs/{job_id}/units/{unit_id}#lti_token={quote(token)}")


@bp.get("/jwks")
def jwks():
    """Public key set of the tool."""
    return {"keys": [Registration.get_jwk(_state().public_key)]}
