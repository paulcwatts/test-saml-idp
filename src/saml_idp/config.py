"""Configuration for the SAML application."""

from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any, Required, TypedDict

from pydantic import HttpUrl, Json
from pydantic_settings import BaseSettings, SettingsConfigDict


class User(TypedDict):
    """Configuration for one test user."""

    username: Required[str]
    password: Required[str]


class Settings(BaseSettings):
    """SAML config settings."""

    saml_idp_entity_id: str
    """The entity ID of the SAML IdP."""

    saml_idp_base_url: HttpUrl
    """The base URL of the SAML IdP."""

    saml_idp_metadata_cert: str = ""
    """The certificate used for the SAML metadata."""

    saml_idp_metadata_key: str = ""
    """The key used for the SAML metadata."""

    saml_idp_metadata_cert_file: str = ""
    """The path of the SAML metadata certificate file."""

    saml_idp_metadata_key_file: str = ""
    """The path of the SAML metadata key file."""

    saml_idp_users: Json[list[User]] | None = None
    """The list of test users for the IdP."""

    check_saml_idp_user: Callable[[str, str], Coroutine[Any, Any, bool]] | None = None
    """The function used to check whether a user is valid."""

    model_config = SettingsConfigDict(env_file=".env")

    def model_post_init(self, __context: Any) -> None:
        """Initialize the certificate parameters."""
        if not self.saml_idp_metadata_cert and self.saml_idp_metadata_cert_file:
            with Path(self.saml_idp_metadata_cert_file).open() as f:
                self.saml_idp_metadata_cert = f.read()
        if not self.saml_idp_metadata_key and self.saml_idp_metadata_key_file:
            with Path(self.saml_idp_metadata_key_file).open() as f:
                self.saml_idp_metadata_key = f.read()
