"""Test SAML IdP implementation."""

from .config import Settings
from .router import router

__all__ = [
    "router",
    "Settings",
]
