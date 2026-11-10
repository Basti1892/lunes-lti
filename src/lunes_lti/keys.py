"""Key material of the tool, generated on first start in the data directory and never committed.

- ``tool-private.pem`` / ``tool-public.pem``: RSA key pair of the tool. The LMS verifies messages of the tool
  (Deep Linking responses, AGS token requests) with the public key, published at ``/lti/jwks``.
- ``token-secret``: HMAC secret for the session tokens the app gets after a launch.
"""

import os
import secrets
from pathlib import Path

from jwcrypto.jwk import JWK

PRIVATE_KEY_FILE = "tool-private.pem"
PUBLIC_KEY_FILE = "tool-public.pem"
TOKEN_SECRET_FILE = "token-secret"


def _write_private(path: Path, content: bytes) -> None:
    # Create the file with owner-only permissions (effective on Linux; Windows ignores the mode)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(content)


def ensure_key_pair(data_dir: Path) -> tuple[str, str]:
    """Returns the tool's private and public key as PEM, generating them if they do not exist yet."""
    private_path = data_dir / PRIVATE_KEY_FILE
    public_path = data_dir / PUBLIC_KEY_FILE

    if not private_path.exists():
        key = JWK.generate(kty="RSA", size=2048)
        _write_private(private_path, key.export_to_pem(private_key=True, password=None))
        public_path.write_bytes(key.export_to_pem())
    elif not public_path.exists():
        key = JWK.from_pem(private_path.read_bytes())
        public_path.write_bytes(key.export_to_pem())

    return private_path.read_text(encoding="utf-8"), public_path.read_text(encoding="utf-8")


def ensure_token_secret(data_dir: Path) -> bytes:
    path = data_dir / TOKEN_SECRET_FILE
    if not path.exists():
        _write_private(path, secrets.token_hex(32).encode("ascii"))
    return path.read_bytes().strip()
