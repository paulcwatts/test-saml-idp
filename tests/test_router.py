from pathlib import Path

import pytest
from httpx import AsyncClient
from lxml import etree
from starlette import status

from saml_idp import Settings

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _set_users(settings: Settings) -> None:
    """Add users for these tests."""
    settings.saml_idp_users = [{"username": "taylorswift", "password": "all2well"}]


async def test_metadata_xml(ac: AsyncClient) -> None:
    """You can retrieve the metadata."""
    response = await ac.get("/metadata.xml")
    assert response.status_code == status.HTTP_200_OK
    assert "text/xml" in response.headers["content-type"]
    xml = response.content.decode()
    assert "http://localhost:8000/idp" in xml
    assert "http://localhost:8000/signin" in xml
    assert "http://localhost:8000/logout" in xml

    # Make sure the metadata validates
    schema_doc = (
        Path(__file__).parent.resolve() / "schema" / "saml-schema-metadata-2.0.xsd"
    )
    with schema_doc.open("rb") as f:
        xmlschema_doc = etree.parse(f)
        schema = etree.XMLSchema(xmlschema_doc)
        schema.assertValid(etree.fromstring(xml))


async def test_login_get(ac: AsyncClient) -> None:
    """You can get the login page."""
    response = await ac.get("/login")
    assert response.status_code == status.HTTP_OK, response.content
    assert "text/html" in response.headers["content-type"]
    assert b"taylorswift" not in response.content


async def test_login_show_users(ac: AsyncClient, settings: Settings) -> None:
    """You can show the user credentials."""
    settings.saml_idp_show_users = True
    response = await ac.get("/login")
    assert response.status_code == status.HTTP_200_OK, response.content
    assert b"taylorswift" in response.content
