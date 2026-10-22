"""Fetch a URL and convert its response headers for evaluation."""

from __future__ import annotations

import http.client
import socket
import ssl
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .audit import evaluate_headers, AuditResult

DEFAULT_UA = f"hdrscope/1.0.0 (+security-header auditor)"
DEFAULT_TIMEOUT = 15


class FetchError(Exception):
    """Raised when the target cannot be reached or URL is invalid."""


def normalize_url(url: str) -> str:
    """Prefix a scheme when the user omitted it (assume HTTPS)."""
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    host = parts.hostname if parts.scheme in ("http", "https") else None
    if parts.scheme not in ("http", "https") or not host:
        raise FetchError(f"invalid URL: {url!r}")
    if not re.match(r"^[A-Za-z0-9._:-]+$", parts.netloc):
        raise FetchError(f"invalid URL: {url!r}")
    return url


def _headers_dict(response) -> dict:
    """http.client.HTTPResponse.headers-like -> {name: [values]}."""
    out = {}
    for name, value in response.getheaders() if hasattr(response, "getheaders") else []:
        out.setdefault(name, []).append(value)
    # Set-Cookie must not be collapsed by urllib's headers API:
    raw = response.headers if hasattr(response, "headers") else None
    if raw is not None and hasattr(raw, "get_all"):
        cookies = raw.get_all("Set-Cookie")
        if cookies and cookies != out.get("Set-Cookie", []):
            out["Set-Cookie"] = cookies
    return out


def fetch_url(url: str, timeout: int = DEFAULT_TIMEOUT) -> AuditResult:
    """GET ``url`` (following redirects), evaluate the final response."""
    url = normalize_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = _headers_dict(resp)
            http_status = resp.status
            final_url = resp.url
    except (urllib.error.HTTPError,) as e:
        # Non-2xx after redirects still carries headers worth auditing.
        headers = _headers_dict(e)
        http_status = e.code
        final_url = url
    except (urllib.error.URLError, ssl.SSLError, socket.timeout,
            http.client.HTTPException, ConnectionError, ValueError) as e:
        reason = getattr(e, "reason", e)
        raise FetchError(f"cannot reach {url}: {reason}") from e

    result = evaluate_headers(headers, http_status=http_status, url=url)
    result.final_url = final_url
    return result


def audit_url(url: str, timeout: int = DEFAULT_TIMEOUT) -> AuditResult:
    """Public alias for :func:`fetch_url`."""
    return fetch_url(url, timeout=timeout)
