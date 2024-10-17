"""SAML2 Logout request model and field."""

from datetime import datetime
from typing import Annotated, Any

from pydantic import HttpUrl, PlainValidator, TypeAdapter

from saml_idp.utils import get_elem_from_path, inflate_and_decode


# This cannot be a pydantic model, otherwise FastAPI doesn't allow it in a query param
class LogoutRequest:
    """Data for SAML Logout Request."""

    id: str
    issue_instant: datetime
    not_on_or_after: datetime
    destination: HttpUrl
    issuer: str
    name_id: str
    session_index: str


DateTimeValidate = TypeAdapter(datetime)
HttpUrlValidate = TypeAdapter(HttpUrl)


def validate_logout_request(data: Any) -> LogoutRequest:
    """Decode and parse SAML request XML."""
    tree = inflate_and_decode(data)
    if tree.tag != "{urn:oasis:names:tc:SAML:2.0:protocol}LogoutRequest":
        msg = "Not a logout request."
        raise ValueError(msg)

    req = LogoutRequest()
    req.id = tree.get("ID")
    req.issue_instant = DateTimeValidate.validate_python(tree.get("IssueInstant"))
    req.not_on_or_after = DateTimeValidate.validate_python(tree.get("NotOnOrAfter"))
    req.destination = HttpUrlValidate.validate_python(tree.get("Destination"))

    elems = get_elem_from_path(tree, "/saml2p:LogoutRequest/saml2:Issuer")
    if len(elems) > 0:
        req.issuer = elems[0].text
    else:
        msg = "No issuer found in request"
        raise ValueError(msg)

    elems = get_elem_from_path(tree, "/saml2p:LogoutRequest/saml2:NameID")
    if len(elems) > 0:
        req.name_id = elems[0].text
    else:
        msg = "No name_id found in request"
        raise ValueError(msg)

    elems = get_elem_from_path(tree, "/saml2p:LogoutRequest/saml2p:SessionIndex")
    if len(elems) > 0:
        req.session_index = elems[0].text
    else:
        msg = "No session_index found in request"
        raise ValueError(msg)

    return req


LogoutRequestField = Annotated[LogoutRequest, PlainValidator(validate_logout_request)]
