from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from saml_idp.models import AuthnRequestField
from saml_idp.utils import deflate_and_encode

REQUEST = """
<saml2p:AuthnRequest
    xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    AssertionConsumerServiceURL="https://example.com/saml2/idpresponse"
    Destination="https://localhost:8000/auth/signin"
    ID="_c0bce021-ddb3-47cb-848b-b257fbbcb9f4"
    IssueInstant="2024-01-12T20:45:56.329Z"
    Version="2.0"
 >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                  >http://myissuer.com</saml2:Issuer>
</saml2p:AuthnRequest>
"""

Validator = TypeAdapter(AuthnRequestField)


def test_parse_request() -> None:
    """Parses a SAML request."""
    value = Validator.validate_python(deflate_and_encode(REQUEST))
    assert value.id == "_c0bce021-ddb3-47cb-848b-b257fbbcb9f4"
    assert value.issue_instant == datetime(2024, 1, 12, 20, 45, 56, 329000, tzinfo=UTC)
    assert str(value.assertion_consumer_service_url) == (
        "https://example.com/saml2/idpresponse"
    )
    assert str(value.destination) == "https://localhost:8000/auth/signin"
    assert value.issuer == "http://myissuer.com"


def test_invalid_tag() -> None:
    """Check for an invalid tag."""
    req = "<div></div>"
    with pytest.raises(ValidationError, match="Not an authn request"):
        Validator.validate_python(deflate_and_encode(req))


def test_no_issuer() -> None:
    """Require a valid issuer."""
    req = """
    <saml2p:AuthnRequest
    xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    AssertionConsumerServiceURL="https://example.com/saml2/idpresponse"
    Destination="https://localhost:8000/auth/signin"
    ID="_c0bce021-ddb3-47cb-848b-b257fbbcb9f4"
    IssueInstant="2024-01-12T20:45:56.329Z"
    Version="2.0"/>
    """
    with pytest.raises(ValidationError, match="No issuer"):
        Validator.validate_python(deflate_and_encode(req))
