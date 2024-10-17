"""SAML2 Logout Response model."""

import uuid
from datetime import datetime

from lxml import etree
from pydantic import BaseModel, HttpUrl

from saml_idp.utils import SAML, SAMLP, encode_response, saml2_timestamp


class LogoutResponse(BaseModel):
    """The response to a Logout request."""

    issue_instant: datetime
    destination: HttpUrl
    in_response_to: str
    issuer: str
    status_code: str

    def to_xml(self) -> etree:
        """Build an XML file from the model."""
        issue_instant = saml2_timestamp(self.issue_instant)
        response_attrs = {
            "ID": f"_{uuid.uuid4()}",
            "Version": "2.0",
            "InResponseTo": self.in_response_to,
            "IssueInstant": issue_instant,
            "Destination": str(self.destination),
        }
        issuer = SAML.Issuer(self.issuer)
        status = SAMLP.Status(SAMLP.StatusCode(Value=self.status_code))
        return SAMLP.LogoutResponse(issuer, status, **response_attrs)

    def to_response(self) -> str:
        """Generate an XML response."""
        return encode_response(self.to_xml())
