from pathlib import Path

import pytest
from httpx import AsyncClient
from lxml import etree
from starlette import status

pytestmark = pytest.mark.asyncio


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
