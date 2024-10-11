"""SAML IdP dependencies."""

from functools import lru_cache
from typing import Annotated

from fastapi import Cookie, Depends

from .config import Settings, User


@lru_cache
def get_settings() -> Settings:
    """Return the SAML settings object."""
    # pyright thinks the non-default attributes are required, but they are
    # filled in by the env
    return Settings()  # pyright: ignore [reportCallIssue]


GetSettings = Annotated[Settings, Depends(get_settings)]


async def get_user(
    settings: GetSettings,
    session_id: Annotated[str | None, Cookie()] = None,
) -> User | None:
    """Get the current user."""
    if session_id:
        return await settings.get_user_from_session(session_id)
    return None


GetUser = Annotated[User | None, Depends(get_user)]
