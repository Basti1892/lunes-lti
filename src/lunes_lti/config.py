"""Configuration of the service, read from a TOML file without secrets.

The tool's key pair and the token secret are not part of the configuration; the service generates them in
``data_dir`` (see ``keys.py``).
"""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class Platform:
    """Registration of the tool in one LMS (LTI 1.3 "platform")."""

    issuer: str
    client_id: str
    auth_login_url: str
    auth_token_url: str
    key_set_url: str
    deployment_ids: list[str]


@dataclass(frozen=True)
class Config:
    # Origin (plus base path, if any) that serves both the web app and this service below /lti,
    # e.g. "https://lunes-app-test.tuerantuer.org" or "http://localhost:8080" in development.
    base_url: str
    data_dir: Path
    platforms: list[Platform] = field(default_factory=list)
    # Lifetime of the session token the app gets after a launch, in seconds
    token_lifetime: int = 2 * 60 * 60
    # API of the Lunes CMS the web app uses, for the vocabulary set picker of Deep Linking,
    # e.g. "https://lunes-test.tuerantuer.org/api/v2". Without it, Deep Linking shows an error; launches still work.
    cms_url: str | None = None

    @property
    def launch_url(self) -> str:
        return f"{self.base_url}/lti/launch"

    @property
    def cookie_path(self) -> str:
        """Path of the LTI cookies as the browser sees it, including a base path of the host."""
        return urlparse(self.base_url).path + "/lti/"

    @property
    def database_path(self) -> Path:
        return self.data_dir / "lunes-lti.sqlite3"


def load_config(path: str | Path) -> Config:
    path = Path(path)
    with path.open("rb") as file:
        raw = tomllib.load(file)

    data_dir = Path(raw.get("data_dir", "data"))
    if not data_dir.is_absolute():
        # Relative to the config file, so the service does not depend on the working directory
        data_dir = path.parent / data_dir

    return Config(
        base_url=raw["base_url"].rstrip("/"),
        data_dir=data_dir,
        platforms=[Platform(**platform) for platform in raw.get("platforms", [])],
        token_lifetime=int(raw.get("token_lifetime", Config.token_lifetime)),
        cms_url=raw["cms_url"].rstrip("/") if raw.get("cms_url") else None,
    )
