from datetime import UTC, datetime
from pathlib import Path

from lxml import etree
from pydantic import HttpUrl

from saml_idp.models import LogoutResponse


def test_logout_response() -> None:
    """Construct a logout response."""
    issue_instant = datetime.now(UTC)
    response = LogoutResponse(
        issue_instant=issue_instant,
        issuer="https://advis.network/issuer",
        destination=HttpUrl("https://advis.network/destination"),
        in_response_to="_yyy",
        status_code="urn:oasis:names:tc:SAML:2.0:status:Success",
    )
    xml = response.to_xml()

    # Make sure the metadata validates
    schema_doc = (
        Path(__file__).parent.parent.resolve()
        / "schema"
        / "saml-schema-protocol-2.0.xsd"
    )
    with schema_doc.open("rb") as f:
        xmlschema_doc = etree.parse(f)
        schema = etree.XMLSchema(xmlschema_doc)
        schema.assertValid(xml)
