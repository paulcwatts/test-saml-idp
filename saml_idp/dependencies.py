"""SAML IdP dependencies."""

from functools import lru_cache

from .config import Settings


@lru_cache
def get_settings() -> Settings:
    """Return the SAML settings object."""
    # pyright thinks the non-default attributes are required, but they are
    # filled in by the env
    return Settings()  # pyright: ignore [reportCallIssue]
