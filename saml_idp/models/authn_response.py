"""Model for SAML Authn Response."""

import uuid
from datetime import datetime

import signxml
from lxml import etree
from pydantic import BaseModel, HttpUrl
from signxml import CanonicalizationMethod, XMLSigner

from saml_idp import Settings
from saml_idp.utils import DS, SAML, SAMLP, encode_response, saml2_timestamp


class AuthnResponse(BaseModel):
    """The response to an Authn request."""

    issue_instant: datetime
    destination: HttpUrl
    in_response_to: str
    issuer: HttpUrl
    status_code: str
    subject_name_id_format: str
    subject_name_id: str
    subject_not_on_or_after: datetime
    conditions_not_before: datetime
    conditions_not_on_or_after: datetime
    audience_restriction: str
    attributes: dict[str, str]
    authn_instant: datetime
    authn_context_class_ref: str
    session_index: str

    def to_xml(self, settings: Settings) -> etree:
        """Build an XML file from the model."""
        issue_instant = saml2_timestamp(self.issue_instant)
        response_attrs = {
            "ID": f"_{uuid.uuid4()}",
            "Version": "2.0",
            "InResponseTo": self.in_response_to,
            "IssueInstant": issue_instant,
            "Destination": str(self.destination),
        }
        status = SAMLP.Status(SAMLP.StatusCode(Value=self.status_code))
        subject = SAML.Subject(
            SAML.NameID(self.subject_name_id, Format=self.subject_name_id_format),
            SAML.SubjectConfirmation(
                SAML.SubjectConfirmationData(
                    InResponseTo=self.in_response_to,
                    NotOnOrAfter=saml2_timestamp(self.subject_not_on_or_after),
                    Recipient=str(self.destination),
                ),
                Method="urn:oasis:names:tc:SAML:2.0:cm:bearer",
            ),
        )
        conditions = SAML.Conditions(
            SAML.AudienceRestriction(SAML.Audience(self.audience_restriction)),
            NotBefore=saml2_timestamp(self.conditions_not_before),
            NotOnOrAfter=saml2_timestamp(self.conditions_not_on_or_after),
        )
        assertion_id = f"_{uuid.uuid4()}"
        authn_statement = SAML.AuthnStatement(
            SAML.AuthnContext(SAML.AuthnContextClassRef(self.authn_context_class_ref)),
            AuthnInstant=saml2_timestamp(self.authn_instant),
            SessionIndex=self.session_index,
        )
        if self.attributes:
            saml_attributes = [
                SAML.Attribute(SAML.AttributeValue(value), Name=name)
                for name, value in self.attributes.items()
            ]
            attr_statement = [SAML.AttributeStatement(*saml_attributes)]
        else:
            attr_statement = []

        assertion = SAML.Assertion(
            SAML.Issuer(str(self.issuer)),
            DS.Signature(Id="placeholder"),
            subject,
            conditions,
            *attr_statement,
            authn_statement,
            ID=assertion_id,
            Version="2.0",
            IssueInstant=issue_instant,
        )
        signer = XMLSigner(
            c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
        )
        signer.namespaces = {None: signxml.namespaces.ds}
        signed_assertion = signer.sign(
            assertion,
            key=settings.saml_idp_metadata_key,
            cert=settings.saml_idp_metadata_cert,
        )

        return SAMLP.Response(
            SAML.Issuer(str(self.issuer)),
            status,
            signed_assertion,
            **response_attrs,
        )

    def to_response(self, settings: Settings) -> str:
        """Generate an XML response."""
        return encode_response(self.to_xml(settings))
