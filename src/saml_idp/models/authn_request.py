"""Model and validation for Authn Request."""

from datetime import datetime
from typing import Annotated, Any

from pydantic import HttpUrl, PlainValidator, TypeAdapter

from saml_idp.utils import get_elem_from_path, inflate_and_decode


# This cannot be a pydantic model, otherwise FastAPI doesn't allow it in a query param
class AuthnRequest:
    """Data from a SAML Authentication Request."""

    id: str
    issue_instant: datetime
    assertion_consumer_service_url: HttpUrl
    destination: HttpUrl
    issuer: str


DateTimeValidate = TypeAdapter(datetime)
HttpUrlValidate = TypeAdapter(HttpUrl)


def validate_authn_request(data: Any) -> AuthnRequest:
    """Decode and parse SAML request XML."""
    tree = inflate_and_decode(data)
    # Get the attributes from the authnrequest
    if tree.tag != "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest":
        msg = "Not an authn request."
        raise ValueError(msg)

    req = AuthnRequest()
    req.id = tree.get("ID")
    req.issue_instant = DateTimeValidate.validate_python(tree.get("IssueInstant"))
    req.assertion_consumer_service_url = HttpUrlValidate.validate_python(
        tree.get("AssertionConsumerServiceURL"),
    )
    req.destination = HttpUrlValidate.validate_python(tree.get("Destination"))

    elems = get_elem_from_path(tree, "/saml2p:AuthnRequest/saml2:Issuer")
    if len(elems) > 0:
        req.issuer = elems[0].text
    else:
        msg = "No issuer found in request"
        raise ValueError(msg)
    return req


AuthnRequestField = Annotated[AuthnRequest, PlainValidator(validate_authn_request)]
