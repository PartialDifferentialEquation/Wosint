"""Shared HTTP plumbing for API modules.

A single :class:`httpx.AsyncClient` is reused for the lifetime of a scan so
that connections are pooled across modules rather than being torn down and
rebuilt for every lookup.
"""

from __future__ import annotations

from typing import Any

import httpx

from .settings import Settings


class HttpError(RuntimeError):
    """Raised when a request fails or returns an unusable response.

    Attributes:
        status_code: The HTTP status, when the request reached the server at
            all. Modules use this to tell "no such account" (404) apart from
            "we were blocked or rate limited", which are very different answers
            to report to an analyst.
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code

    @property
    def is_not_found(self) -> bool:
        return self.status_code == 404


def build_client(settings: Settings) -> httpx.AsyncClient:
    """Create the client shared by every API module in a scan."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(settings.http_timeout),
        headers={"User-Agent": settings.user_agent, "Accept": "application/json, text/plain, */*"},
        follow_redirects=True,
        limits=httpx.Limits(max_connections=16, max_keepalive_connections=8),
    )


async def get_json(client: httpx.AsyncClient, url: str, **kwargs: Any) -> Any:
    """GET ``url`` and decode the response as JSON.

    Raises:
        HttpError: On a transport failure, an error status, or a body that is
            not valid JSON.
    """
    response = await _get(client, url, **kwargs)
    try:
        return response.json()
    except ValueError as exc:
        raise HttpError(f"{url} did not return valid JSON") from exc


async def get_text(client: httpx.AsyncClient, url: str, **kwargs: Any) -> str:
    """GET ``url`` and return the response body as text.

    Raises:
        HttpError: On a transport failure or an error status.
    """
    return (await _get(client, url, **kwargs)).text


async def head_ok(client: httpx.AsyncClient, url: str, **kwargs: Any) -> bool:
    """Whether ``url`` exists, without downloading or raising.

    Used for presence checks where a 404 is an ordinary answer rather than a
    failure worth reporting.
    """
    try:
        response = await client.get(url, **kwargs)
    except httpx.HTTPError:
        return False
    return response.status_code < 400


async def _get(client: httpx.AsyncClient, url: str, **kwargs: Any) -> httpx.Response:
    try:
        response = await client.get(url, **kwargs)
    except httpx.HTTPError as exc:
        # Several httpx transport errors stringify to "", which would leave the
        # analyst staring at a blank reason in the results panel.
        detail = str(exc).strip() or type(exc).__name__
        raise HttpError(f"request to {url} failed: {detail}") from exc
    if response.status_code >= 400:
        raise HttpError(
            f"{url} returned HTTP {response.status_code}", status_code=response.status_code
        )
    return response
