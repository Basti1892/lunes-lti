"""Short-lived session token the app gets after a launch (ADR 0013).

It identifies a launch of this service, not the learner: the only claim besides the times is the launch ID. The app
sends it with its results; the service looks up the launch (and later the AGS line item) by that ID.
"""

import time

import jwt

ISSUER = "lunes-lti"
ALGORITHM = "HS256"


def issue(secret: bytes, launch_id: str, lifetime: int) -> str:
    now = int(time.time())
    claims = {"iss": ISSUER, "lid": launch_id, "iat": now, "exp": now + lifetime}
    return jwt.encode(claims, secret, algorithm=ALGORITHM)


def verify(secret: bytes, token: str) -> str:
    """Returns the launch ID of a valid token. Raises ``jwt.InvalidTokenError`` otherwise (also when expired)."""
    claims = jwt.decode(
        token, secret, algorithms=[ALGORITHM], issuer=ISSUER, options={"require": ["exp", "iat", "lid"]}
    )
    return claims["lid"]
