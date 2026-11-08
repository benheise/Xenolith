"""Small HTTP helper (standard library only) with retries and a polite User-Agent."""

from __future__ import annotations

import gzip
import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import USER_AGENT

INTERMEDIATES = Path(__file__).resolve().parent.parent / "catalog" / "intermediates.pem"


def _context() -> ssl.SSLContext:
    """System trust store plus catalog/intermediates.pem (for vendor sites with incomplete chains)."""
    ctx = ssl.create_default_context()
    if INTERMEDIATES.exists():
        ctx.load_verify_locations(cafile=str(INTERMEDIATES))
    return ctx


SSL_CONTEXT = _context()


def urlopen(req, timeout: float):
    return urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT)


class FetchError(RuntimeError):
    pass


def get(url: str, *, timeout: float = 45, retries: int = 2, accept: str = "*/*") -> bytes:
    last: Exception | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": accept,
            "Accept-Encoding": "gzip",
        })
        try:
            with urlopen(req, timeout) as resp:
                body = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    body = gzip.decompress(body)
                return body
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (400, 401, 403, 404, 410):
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last = e
        time.sleep(1.5 * (attempt + 1))
    raise FetchError(f"{url}: {last}")


def get_json(url: str, **kw) -> dict:
    body = get(url, accept="application/json", **kw)
    try:
        return json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise FetchError(f"{url}: not JSON ({e})") from e


def get_text(url: str, **kw) -> str:
    return get(url, **kw).decode("utf-8-sig", errors="replace")
