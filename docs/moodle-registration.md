# Registering Lunes in Moodle (LTI 1.3)

Needs a site administrator. Tested target: Moodle 4.x. `<base>` is the `base_url` of the service:

- Development: `http://localhost:8080` (webpack dev server of lunes-app, which proxies `/lti` to the service)
- Test server: `https://lunes-app-test.tuerantuer.org`

Use a separate registration (separate tool) per `<base>`; each gets its own client ID.

## 1. Create the tool

Site administration → Plugins → Activity modules → External tool → **Manage tools** → **configure a tool manually**.

| Field                           | Value                                                                                  |
| ------------------------------- | -------------------------------------------------------------------------------------- |
| Tool name                       | Lunes (add "(dev)" for the development registration)                                   |
| Tool URL                        | `<base>/lti/launch`                                                                    |
| LTI version                     | LTI 1.3                                                                                |
| Public key type                 | Server: **Keyset URL** → `<base>/lti/jwks`. Development: **RSA key**, see below        |
| Initiate login URL              | `<base>/lti/login`                                                                     |
| Redirection URI(s)              | `<base>/lti/launch`                                                                    |
| Custom parameters               | empty (set per activity)                                                               |
| Tool configuration usage        | Show in activity chooser and as a preconfigured tool                                   |
| Default launch container        | Embed, without blocks (fallback: New window, see "Cookies" below)                      |
| Supports Deep Linking           | on                                                                                     |
| Content Selection URL           | `<base>/lti/launch`                                                                    |

**Services:**

| Service                                  | Value                       |
| ---------------------------------------- | --------------------------- |
| IMS LTI Assignment and Grade Services    | Use this service for grade sync only |
| IMS LTI Names and Role Provisioning      | Do not use this service     |
| Tool Settings                            | Do not use this service     |

**Privacy** (data minimisation, NFR-04 / NFR-10):

| Field                                  | Value |
| -------------------------------------- | ----- |
| Share launcher's name with tool        | Never |
| Share launcher's email with tool       | Never |
| Accept grades from the tool            | Always (or "Delegate to teacher") |

Moodle still sends its username (`ext` claim) and ID number (`lis` claim); the service drops these claims before
storing anything.

**RSA key for development:** Moodle cannot reach `http://localhost:8080/lti/jwks`. Print the public key with

```bash
flask --app lunes_lti public-key
```

and paste the output (`-----BEGIN PUBLIC KEY----- …`) into "Public key". A plain launch works without the key, but
grades do not: Moodle checks the tool's token request with it. With "Keyset URL" pointing to localhost, Moodle cannot
fetch the key and answers the token request with `404` and the error `fix_jwks_alg(): Argument #1 ($jwks) must be of
type array, null given` (logged by lunes-lti as "LMS rejected the grade"). The key changes only if `data/` is deleted;
then paste it again.

Copy the key without the terminal window, which tends to add spaces or drop line breaks: in Git Bash
`flask --app lunes_lti public-key | clip`, then paste into the field. If the field does not start with
`-----BEGIN PUBLIC KEY-----` and end with `-----END PUBLIC KEY-----`, Moodle answers the token request with
`400 OpenSSL error: … DECODER routines::unsupported`.

If the token request succeeds but sending the score fails with `401 Unauthorized` at `mod/lti/services.php/…/scores`,
the web server does not pass the `Authorization` header to PHP. With Apache and PHP-FPM (`proxy_fcgi`), the Moodle
administrators need `CGIPassAuth On` for the Moodle directory.

## 2. Copy the platform details into `config.toml`

Manage tools → the tool's **View configuration details** icon shows:

| Moodle                     | `config.toml` (`[[platforms]]`) |
| -------------------------- | ------------------------------- |
| Platform ID                | `issuer`                        |
| Client ID                  | `client_id`                     |
| Deployment ID              | `deployment_ids = ["…"]`        |
| Public keyset URL          | `key_set_url`                   |
| Access token URL           | `auth_token_url`                |
| Authentication request URL | `auth_login_url`                |

Restart the service after changing the file.

## 3. Add an activity

In a course: Add an activity or resource → **Lunes** (or External tool → Preconfigured tool: Lunes) → **Select
content**. Lunes opens a picker: choose the profession, then the vocabulary set, then **Auswählen**. Moodle fills in the
activity name and the custom parameters (`job_id`, `unit_id`) and creates the grade item (type "Point", maximum 100).
Save the activity.

The picker reads the professions and sets from the CMS in `cms_url` (`config.toml`). It must be the CMS the web app
uses, because the IDs differ between the CMS instances: the test CMS for the development server (`yarn web`).

A launch redirects to `<base>/jobs/<job ID>/units/<unit ID>#lti_token=…`.

**Grade:** Lunes sends the words correct on the first try out of all words of the word choice exercise; Moodle scales
that to the maximum grade (6 of 8 → 75). Every finished attempt is sent, the gradebook shows the latest. The time of
the attempt appears as feedback of the grade ("Bearbeitungszeit: 3 min 12 s").

After switching on the grade service or "Accept grades", launch the activity again: only new launches carry the AGS
claim. Results of older launches are answered with `409 not_graded`.

**Without Deep Linking** (or for activities created before): set the custom parameters by hand under **Show more…** →
**Custom parameters**:

```
job_id=<job ID>
unit_id=<unit ID>
```

The IDs are in the URL of the web app: open the vocabulary set there, the URL is `/jobs/<job ID>/units/<unit ID>`.
Set the grade (type "Point", maximum e.g. 100) in the section "Grade" of the same form.

## Cookies in the iframe

The login sets two cookies (`lti1p3-session-id`, `lti1p3-state-…`) that the launch needs. They are `Secure`,
`SameSite=None` and `Partitioned`, so they work in a cross-site iframe in browsers that partition third-party
cookies. If a browser blocks them anyway, the login shows "Dein Browser erlaubt keine Cookies in eingebetteten
Inhalten." with a link that opens Lunes in a new tab. If that happens often, set the launch container of the tool or
the activity to "New window".

## Development notes

- `http://localhost` counts as a secure origin in Chrome, Edge and Firefox: the `Secure` cookies work, and the HTTPS
  Moodle page may embed it without a mixed-content block. Use `localhost` everywhere (`base_url`, Moodle registration, browser), not a host name. Safari is
  not supported for local development.
- Chrome and Edge ask on the first launch whether moodle-lunes.tuerantuer.org may access other apps and services on
  this device (German: "Auf andere Apps und Dienste auf diesem Gerät zugreifen"). This is Local Network Access: a
  public site loads `localhost` in an iframe. Click "Allow" ("Zulassen"). If it was blocked by mistake, reset it in the
  site settings of the Moodle page (lock icon in the address bar). Only development is affected; the deployed service
  runs on a public host.
