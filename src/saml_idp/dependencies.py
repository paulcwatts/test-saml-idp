"""SAML IdP dependencies."""

from typing import Annotated

from fastapi import Cookie, Depends

from .config import User, settings


async def get_user(
    session_id: Annotated[str | None, Cookie()] = None,
) -> User | None:
    """Get the current user."""
    if session_id:
        return await settings.get_user_from_session(session_id)
    return None


GetUser = Annotated[User | None, Depends(get_user)]
