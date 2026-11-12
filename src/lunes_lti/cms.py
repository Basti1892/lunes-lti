"""Read access to the Lunes CMS for the vocabulary set picker of Deep Linking and the check at launch (FR-07).

Only the public professions ("jobs") and their vocabulary sets ("units"), the same the web app shows without a content
area code. Uses the standard library: no new dependency for two GET requests.
"""

import json
import typing as t
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

TIMEOUT = 10


class CmsError(Exception):
    """The CMS could not be reached or answered with something unexpected."""


class NotFound(CmsError):
    """The CMS does not offer the requested profession (it answers 403 for unknown or withdrawn ones)."""


@dataclass(frozen=True)
class Job:
    id: int
    name: str


@dataclass(frozen=True)
class Unit:
    id: int
    title: str
    number_words: int


def _get(url: str, timeout: float = TIMEOUT) -> t.Any:
    if urlparse(url).scheme not in ("http", "https"):
        raise CmsError(f"Not an HTTP URL: {url}")
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "lunes-lti"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code in (403, 404):
            raise NotFound(f"GET {url}: {error.code}") from error
        raise CmsError(f"GET {url} failed: {error}") from error
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        raise CmsError(f"GET {url} failed: {error}") from error


def _items(data: t.Any) -> list[dict[str, t.Any]]:
    if not isinstance(data, list):
        raise CmsError("Expected a list")
    return [item for item in data if isinstance(item, dict) and isinstance(item.get("id"), int)]


def list_jobs(cms_url: str) -> list[Job]:
    jobs = [Job(item["id"], str(item.get("name", ""))) for item in _items(_get(f"{cms_url}/jobs"))]
    return sorted(jobs, key=lambda job: job.name.casefold())


def list_units(cms_url: str, job_id: int, timeout: float = TIMEOUT) -> list[Unit]:
    return [
        Unit(item["id"], str(item.get("title", "")), int(item.get("number_words") or 0))
        for item in _items(_get(f"{cms_url}/jobs/{job_id}/units", timeout))
    ]


def find_unit(cms_url: str, job_id: int, unit_id: int, timeout: float = TIMEOUT) -> Unit | None:
    """The vocabulary set if the CMS still offers it in that profession, ``None`` if the profession or the set was
    withdrawn. Raises ``CmsError`` if the CMS cannot answer.
    """
    try:
        units = list_units(cms_url, job_id, timeout)
    except NotFound:
        return None
    return next((unit for unit in units if unit.id == unit_id), None)
