from pathlib import Path

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
