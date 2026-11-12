"""Read access to the Lunes CMS for the vocabulary set picker of Deep Linking.

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


@dataclass(frozen=True)
class Job:
    id: int
    name: str


@dataclass(frozen=True)
class Unit:
    id: int
    title: str
    number_words: int


def _get(url: str) -> t.Any:
    if urlparse(url).scheme not in ("http", "https"):
        raise CmsError(f"Not an HTTP URL: {url}")
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "lunes-lti"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        raise CmsError(f"GET {url} failed: {error}") from error


def _items(data: t.Any) -> list[dict[str, t.Any]]:
    if not isinstance(data, list):
        raise CmsError("Expected a list")
    return [item for item in data if isinstance(item, dict) and isinstance(item.get("id"), int)]


def list_jobs(cms_url: str) -> list[Job]:
    jobs = [Job(item["id"], str(item.get("name", ""))) for item in _items(_get(f"{cms_url}/jobs"))]
    return sorted(jobs, key=lambda job: job.name.casefold())


def list_units(cms_url: str, job_id: int) -> list[Unit]:
    return [
        Unit(item["id"], str(item.get("title", "")), int(item.get("number_words") or 0))
        for item in _items(_get(f"{cms_url}/jobs/{job_id}/units"))
    ]
