"""LTI 1.3 connector between learning management systems and the Lunes web app."""

import logging
import os
from dataclasses import dataclass

import click
from flask import Flask
from pylti1p3.tool_config import ToolConfDict

from . import keys, lti, storage, views
from .config import Config, load_config


@dataclass(frozen=True)
class State:
    config: Config
    tool_conf: ToolConfDict
    public_key: str
    token_secret: bytes


def _configure_logging() -> None:
    """Info messages of the service (e.g. each launch with its role) on stderr, unless the server configures logging."""
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    if not logger.handlers and not logging.getLogger().handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)


def create_app(config: Config | None = None) -> Flask:
    """App factory. Without an explicit config, the TOML file named by ``LUNES_LTI_CONFIG`` is read."""
    if config is None:
        config = load_config(os.environ.get("LUNES_LTI_CONFIG", "config.toml"))

    _configure_logging()
    config.data_dir.mkdir(parents=True, exist_ok=True)
    storage.init_db(config.database_path)
    private_key, public_key = keys.ensure_key_pair(config.data_dir)

    app = Flask(__name__)
    app.extensions["lunes_lti"] = State(
        config=config,
        tool_conf=lti.tool_conf(config, private_key, public_key),
        public_key=public_key,
        token_secret=keys.ensure_token_secret(config.data_dir),
    )
    app.register_blueprint(views.bp)

    @app.cli.command("public-key")
    def print_public_key():
        """Prints the tool's public key (PEM), e.g. for the "RSA key" option of the Moodle registration."""
        click.echo(public_key, nl=False)

    return app
