"""Utilities for constructing relative URLs."""

from typing import TYPE_CHECKING, Any

from starlette.requests import Request

if TYPE_CHECKING:
    from starlette.applications import Starlette  # pragma: nocover
    from starlette.routing import Router  # pragma: nocover


def rel_url_for(req: Request, name: str, /, **path_params: Any) -> str:
    """Provide a relative URL for a path."""
    url_path_provider: Router | Starlette | None = req.scope.get(
        "router"
    ) or req.scope.get("app")
    if url_path_provider is None:
        msg = "`rel_url_for` method can only be used inside a Starlette application."
        raise RuntimeError(msg)
    return url_path_provider.url_path_for(name, **path_params)
