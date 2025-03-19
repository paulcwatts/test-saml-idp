"""Configuration for the SAML application."""

import hashlib
from pathlib import Path
from typing import Any, Literal, NotRequired, Required, TypedDict

from pydantic import HttpUrl, Json
from pydantic_settings import BaseSettings, SettingsConfigDict


class User(TypedDict):
    """Configuration for one test user."""

    username: Required[str]
    password: Required[str]
    attributes: NotRequired[dict[str, str]]


class Settings(BaseSettings):
    """SAML config settings."""

    saml_idp_entity_id: str = ""
    """The entity ID of the SAML IdP."""

    saml_idp_metadata_cert: str = ""
    """The certificate used for the SAML metadata."""

    saml_idp_metadata_key: str = ""
    """The key used for the SAML metadata."""

    saml_idp_metadata_cert_file: str = ""
    """The path of the SAML metadata certificate file."""

    saml_idp_metadata_key_file: str = ""
    """The path of the SAML metadata key file."""

    saml_idp_base_url: HttpUrl | Literal[""] = ""
    """The Base URL used for the URLs in the SAML Metadata."""

    saml_idp_logout_url: HttpUrl | Literal[""] = ""
    """The logout URL to redirect to."""

    saml_idp_users: Json[list[User]] | None = None
    """The list of test users for the IdP."""

    saml_idp_show_users: bool = False
    """Whether to show the user credentials on the login screen."""

    saml_idp_router_prefix: str = ""
    """The prefix under which to include the SAML router."""

    model_config = SettingsConfigDict(env_file=".env")

    def model_post_init(self, __context: Any, /) -> None:
        """Initialize the certificate parameters."""
        if not self.saml_idp_metadata_cert and self.saml_idp_metadata_cert_file:
            with Path(self.saml_idp_metadata_cert_file).open() as f:
                self.saml_idp_metadata_cert = f.read()
        if not self.saml_idp_metadata_key and self.saml_idp_metadata_key_file:
            with Path(self.saml_idp_metadata_key_file).open() as f:
                self.saml_idp_metadata_key = f.read()

    async def authenticate_user(self, username: str, password: str) -> tuple[User, str]:
        """
        Get a user from a username/password combo.

        If it's successful, return a username and session ID. Otherwise, raise an error.
        """
        for user in self.saml_idp_users or []:
            if user["username"] == username and user["password"] == password:
                return user, self.generate_session_id(user)
        msg = "Invalid username or password."
        raise ValueError(msg)

    async def get_user_from_session(self, session_id: str) -> User | None:
        """Return the user from a session."""
        for user in self.saml_idp_users or []:
            if session_id == self.generate_session_id(user):
                return user
        return None

    @classmethod
    def generate_session_id(cls, user: User) -> str:
        """
        Generate a session ID for a user.

        This is *NOT* meant to be secure. It's only meant so we have a way to
        identify a user without a local state or database.
        """
        h = hashlib.new("sha256")
        h.update(user["username"].encode())
        h.update(user["password"].encode())
        return h.hexdigest()


settings = Settings()
