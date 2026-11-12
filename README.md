# lunes-lti

LTI 1.3 connector between learning management systems (Moodle first) and the
[Lunes](https://github.com/digitalfabrik/lunes-app) web app. The LMS launches the tool, the service checks the launch
and redirects into the web app with a short-lived session token. Background: ADRs 0013 to 0021 in the lunes-app
repository (`docs/web/`).

Endpoints, all below the origin of the web app:

- `/lti/login`: OIDC login initiation, called by the LMS
- `/lti/launch`: launch (redirect URI); redirects to `/jobs/<job_id>/units/<unit_id>#lti_token=<token>`. A Deep
  Linking request shows the vocabulary set picker instead. If the CMS no longer offers the set, it shows a message
  instead of the app
- `/lti/deep-link`: steps of the picker (profession, set); sends the chosen set back to the LMS
- `/lti/session`: launch data for the app (`Authorization: Bearer <token>`): `jobId`, `unitId`, `returnUrl`,
  `expiresAt`; `401` if the token is expired, invalid or missing
- `/lti/results`: result of a finished exercise from the app (`Authorization: Bearer <token>`,
  `{"correct": <int>, "total": <int>, "durationSeconds": <int, optional>}`), sent to the LMS gradebook via AGS; only
  for learners, a teacher's launch is a preview (`409 preview`)
- `/lti/jwks`: public key set of the tool

## Development setup (Windows, Git Bash)

```bash
python -m venv .venv
source .venv/Scripts/activate
python -m pip install -e ".[dev]"
cp config.example.toml config.toml
```

Edit `config.toml` (see [docs/moodle-registration.md](docs/moodle-registration.md)), then:

```bash
flask --app lunes_lti run --port 5000
```

The first start creates `data/` with the tool's key pair, the token secret and the SQLite database. Keep `data/` out
of git (it is ignored) and do not share it. Another config file: `LUNES_LTI_CONFIG=path/to/config.toml`.

In lunes-app, `yarn web` serves the app on http://localhost:8080 and proxies `/lti` to `http://127.0.0.1:5000`
(override with `LUNES_LTI_ORIGIN`). Use `http://localhost:8080` as `base_url` and in the Moodle registration.

## Tests

```bash
pytest
```

Tests marked `keys` generate throwaway RSA keys; `pytest -m "not keys"` skips them.

## Data

The SQLite database holds nonce, state and the cached launch (for two hours, without name, e-mail, username or ID
number) and per launch the pseudonymous user ID (`sub`), course, resource link, AGS line item and endpoint claim, the
return URL of the LMS and the selected job and unit.
