from pathlib import Path

import pytest
from pydantic_core import Url

from saml_idp import Settings

path = Path(__file__).parent.resolve() / "files"


def test_metadata_file() -> None:
    """The file parameters will read the file contents."""
    settings = Settings(
        saml_idp_entity_id="x",
        saml_idp_base_url=Url("http://localhost:8000"),
        saml_idp_metadata_cert_file=str(path / "metadata.crt"),
        saml_idp_metadata_key_file=str(path / "metadata.key"),
    )
    assert settings.saml_idp_metadata_cert.startswith("-----BEGIN CERTIFICATE-----")
    assert settings.saml_idp_metadata_key.startswith("-----BEGIN PRIVATE KEY-----")


def test_metadata_file_ignored() -> None:
    """If the metadata cert/key values are already populated, the files are ignored."""
    settings = Settings(
        saml_idp_entity_id="x",
        saml_idp_base_url=Url("http://localhost:8000"),
        saml_idp_metadata_cert="mycert",
        saml_idp_metadata_key="mykey",
        saml_idp_metadata_cert_file=str(path / "metadata.crt"),
        saml_idp_metadata_key_file=str(path / "metadata.key"),
    )
    assert settings.saml_idp_metadata_cert == "mycert"
    assert settings.saml_idp_metadata_key == "mykey"


@pytest.mark.asyncio
async def test_authenticate_user() -> None:
    """You can authenticate a user."""
    settings = Settings(
        saml_idp_entity_id="x",
        saml_idp_base_url=Url("http://localhost:8000"),
        saml_idp_users='[{"username": "taylorswift", "password": "all2well"}]',  # pyright: ignore[reportArgumentType]
    )
    user, session_id = await settings.authenticate_user("taylorswift", "all2well")
    assert user["username"] == "taylorswift"
    assert session_id is not None


@pytest.mark.asyncio
async def test_authenticate_user_fail() -> None:
    """Authenticate user throws an error if failed."""
    settings = Settings(
        saml_idp_entity_id="x",
        saml_idp_base_url=Url("http://localhost:8000"),
        saml_idp_users='[{"username": "taylorswift", "password": "all2well"}]',  # pyright: ignore[reportArgumentType]
    )
    with pytest.raises(ValueError, match=r"Invalid username or password."):
        await settings.authenticate_user("taylorswift", "notpassword")


@pytest.mark.asyncio
async def test_get_user_from_session() -> None:
    """You can get a user from a session."""
    settings = Settings(
        saml_idp_entity_id="x",
        saml_idp_base_url=Url("http://localhost:8000"),
        saml_idp_users='[{"username": "taylorswift", "password": "all2well"}]',  # pyright: ignore[reportArgumentType]
    )
    user = await settings.get_user_from_session(
        settings.generate_session_id(
            {"username": "taylorswift", "password": "all2well"},
        ),
    )
    assert user is not None


@pytest.mark.asyncio
async def test_get_user_from_session_fail() -> None:
    """Failing to get a user returns None."""
    settings = Settings(
        saml_idp_entity_id="x",
        saml_idp_base_url=Url("http://localhost:8000"),
    )
    user = await settings.get_user_from_session(
        settings.generate_session_id({"username": "a", "password": "b"}),
    )
    assert user is None
