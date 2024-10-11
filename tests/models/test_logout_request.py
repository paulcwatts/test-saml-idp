from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from saml_idp.models import LogoutRequestField
from saml_idp.utils import deflate_and_encode

REQUEST = """<saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                      Destination="https://localhost:8000/auth/logout"
                      ID="_bf3ed8e8-b087-43c9-b936-4dd154542eeb"
                      IssueInstant="2024-01-16T17:43:35.553Z"
                      NotOnOrAfter="2024-01-16T17:48:35.553Z"
                      Version="2.0"
                      >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                  >http://myissuer.com/</saml2:Issuer>
    <saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                  >davidbowie</saml2:NameID>
    <saml2p:SessionIndex>xyxyxyxyxy</saml2p:SessionIndex>
</saml2p:LogoutRequest>
"""

Validator = TypeAdapter(LogoutRequestField)


def test_logout_request() -> None:
    """Parses a SAML Logout request."""
    value = Validator.validate_python(deflate_and_encode(REQUEST))
    assert value.id == "_bf3ed8e8-b087-43c9-b936-4dd154542eeb"
    assert value.issue_instant == datetime(2024, 1, 16, 17, 43, 35, 553000, tzinfo=UTC)
    assert value.not_on_or_after == datetime(
        2024, 1, 16, 17, 48, 35, 553000, tzinfo=UTC
    )
    assert str(value.destination) == "https://localhost:8000/auth/logout"
    assert value.issuer == "http://myissuer.com/"
    assert value.name_id == "davidbowie"
    assert value.session_index == "xyxyxyxyxy"


def test_invalid_log() -> None:
    """Check for invalid tag."""
    req = "<div></div>"
    with pytest.raises(ValidationError, match="Not a logout request"):
        Validator.validate_python(deflate_and_encode(req))


def test_no_issuer() -> None:
    """Require a valid issue."""
    req = """<saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                      Destination="https://localhost:8000/auth/logout"
                      ID="_bf3ed8e8-b087-43c9-b936-4dd154542eeb"
                      IssueInstant="2024-01-16T17:43:35.553Z"
                      NotOnOrAfter="2024-01-16T17:48:35.553Z"
                      Version="2.0"
                      >
    <saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                  >davidbowie</saml2:NameID>
    <saml2p:SessionIndex>xyxyxyxyxy</saml2p:SessionIndex>
</saml2p:LogoutRequest>
"""
    with pytest.raises(ValidationError, match="No issuer"):
        Validator.validate_python(deflate_and_encode(req))


def test_no_name_id() -> None:
    """Require a valid name ID."""
    req = """<saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                      Destination="https://localhost:8000/auth/logout"
                      ID="_bf3ed8e8-b087-43c9-b936-4dd154542eeb"
                      IssueInstant="2024-01-16T17:43:35.553Z"
                      NotOnOrAfter="2024-01-16T17:48:35.553Z"
                      Version="2.0"
                      >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                  >http://myissuer.com/</saml2:Issuer>
    <saml2p:SessionIndex>xyxyxyxyxy</saml2p:SessionIndex>
</saml2p:LogoutRequest>
"""
    with pytest.raises(ValidationError, match="No name_id"):
        Validator.validate_python(deflate_and_encode(req))


def test_no_session_index() -> None:
    """Require a valid session index."""
    req = """<saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                      Destination="https://localhost:8000/auth/logout"
                      ID="_bf3ed8e8-b087-43c9-b936-4dd154542eeb"
                      IssueInstant="2024-01-16T17:43:35.553Z"
                      NotOnOrAfter="2024-01-16T17:48:35.553Z"
                      Version="2.0"
                      >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                  >http://myissuer.com/</saml2:Issuer>
    <saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                  >davidbowie</saml2:NameID>
</saml2p:LogoutRequest>
"""
    with pytest.raises(ValidationError, match="No session_index"):
        Validator.validate_python(deflate_and_encode(req))
