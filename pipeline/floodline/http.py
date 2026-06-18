"""Shared HTTP session with GitHub auth, retries, and a fail-loud download."""

from __future__ import annotations

import logging
import os
import time
from urllib.parse import urlsplit

import requests

from . import sources

log = logging.getLogger("floodline")

# Hosts the GITHUB_TOKEN may be sent to. Anything else (e.g. cisa.gov) must NOT
# receive the bearer -- sending it leaks the credential to a third party.
_GITHUB_HOSTS = {"github.com", "api.github.com", "raw.githubusercontent.com"}

_session: requests.Session | None = None


def session() -> requests.Session:
    """A process-wide session. The GITHUB_TOKEN is attached per-request (see
    ``get``), never as a session-wide default, so non-GitHub hosts never see it."""
    global _session
    if _session is None:
        s = requests.Session()
        s.headers["User-Agent"] = sources.USER_AGENT
        _session = s
    return _session


def _rate_limit_wait(resp: requests.Response) -> int:
    """Seconds to wait from Retry-After or GitHub's X-RateLimit-Reset, capped so
    a single stuck request can't hang the whole run. 0 if not rate-limited."""
    retry_after = resp.headers.get("Retry-After")
    if retry_after and retry_after.isdigit():
        return min(int(retry_after), 120)
    if resp.headers.get("X-RateLimit-Remaining") == "0":
        reset = resp.headers.get("X-RateLimit-Reset")
        if reset and reset.isdigit():
            # We can't read the clock in tests; cap to a sane bounded wait.
            return 60
    return 0


def _auth_header(url: str) -> dict[str, str]:
    """Bearer header only for GitHub hosts; empty for everything else."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return {}
    host = urlsplit(url).hostname or ""
    if host in _GITHUB_HOSTS:
        return {"Authorization": f"Bearer {token}"}
    return {}


def get(url: str, *, accept: str | None = None, retries: int = 3) -> requests.Response:
    """GET with simple exponential backoff. Raises on persistent failure --
    callers let it propagate so a failed run exits nonzero and leaves the prior
    committed data intact."""
    headers = {"Accept": accept} if accept else {}
    headers.update(_auth_header(url))
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            resp = session().get(url, headers=headers, timeout=sources.HTTP_TIMEOUT)
            if resp.status_code == 200:
                return resp
            # 403/429 may carry a rate-limit reset; honor it (capped) instead of
            # a blind short backoff that would exhaust retries inside the window.
            if resp.status_code in (403, 429, 500, 502, 503, 504) and attempt < retries:
                wait = _rate_limit_wait(resp) or 2 ** attempt
                log.warning("GET %s -> %s, retry %d/%d in %ds",
                            url, resp.status_code, attempt, retries, wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
        except requests.RequestException as exc:  # noqa: PERF203
            last = exc
            if attempt < retries:
                wait = 2 ** attempt
                log.warning("GET %s failed (%s), retry %d/%d in %ds",
                            url, exc, attempt, retries, wait)
                time.sleep(wait)
                continue
            raise
    if last:
        raise last
    raise RuntimeError(f"GET {url} exhausted retries")
