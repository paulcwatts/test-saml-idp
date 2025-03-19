from datetime import UTC, datetime
from pathlib import Path

import pytest
from lxml import etree
from pydantic import HttpUrl
from signxml import XMLVerifier

from saml_idp.config import settings
from saml_idp.models import AuthnResponse


def _make_response(attributes: dict[str, str]) -> AuthnResponse:
    issue_instant = datetime.now(UTC)
    not_on_or_after = datetime.now(UTC)
    return AuthnResponse(
        issue_instant=issue_instant,
        issuer=HttpUrl("https://example.com/issuer"),
        destination=HttpUrl("https://example.com//destination"),
        in_response_to="_yyyy",
        status_code="urn:oasis:names:tc:SAML:2.0:status:Success",
        subject_name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        subject_name_id="foo@example.com",
        subject_not_on_or_after=not_on_or_after,
        conditions_not_before=not_on_or_after,
        conditions_not_on_or_after=not_on_or_after,
        attributes=attributes,
        audience_restriction="https://example.com/samlauth/",
        authn_instant=issue_instant,
        authn_context_class_ref="urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
        session_index="session_index",
    )


@pytest.mark.parametrize("attributes", [{}, {"foo": "bar"}])
def test_authn_response(attributes: dict[str, str]) -> None:
    """Construct an authn response."""
    response = _make_response(attributes)
    xml = response.to_xml(settings)

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

    # Verify the assertion signature
    assertion = xml.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    result = XMLVerifier().verify(assertion, x509_cert=settings.saml_idp_metadata_cert)
    assert not isinstance(result, list)
    assertion_data = result.signed_xml
    assert assertion_data is not None


def test_attributes() -> None:
    """You can set SAML attributes."""
    response = _make_response({"foo": "bar"})
    xml = response.to_xml(settings)
    attr = xml.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute")
    assert attr.get("Name") == "foo"
    assert attr[0].text == "bar"
