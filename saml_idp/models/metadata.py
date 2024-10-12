"""SAML metadata model."""

from datetime import datetime

import signxml
from lxml import etree
from lxml.builder import ElementMaker
from pydantic import BaseModel

from saml_idp.utils import saml2_timestamp

META = ElementMaker(
    namespace="urn:oasis:names:tc:SAML:2.0:metadata",
    nsmap={None: "urn:oasis:names:tc:SAML:2.0:metadata"},
)
DS = ElementMaker(namespace=signxml.namespaces.ds, nsmap={"ds": signxml.namespaces.ds})


class SamlMetadata(BaseModel):
    """SAML metadata model."""

    entity_id: str
    signon_url: str
    logout_url: str
    valid_until: datetime
    cert: str

    def to_xml(self) -> etree:
        """Serialize to XML."""
        key_info = DS.KeyInfo(DS.X509Data(DS.X509Certificate(self.cert)))
        key_desc = META.KeyDescriptor(key_info, use="signing")
        logout = META.SingleLogoutService(
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Location=self.logout_url,
        )
        name_id = META.NameIDFormat(
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        )
        signon = META.SingleSignOnService(
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Location=self.signon_url,
        )
        sso_desc = META.IDPSSODescriptor(
            key_desc,
            logout,
            name_id,
            signon,
            WantAuthnRequestsSigned="false",
            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol",
        )
        return META.EntityDescriptor(
            sso_desc,
            validUntil=saml2_timestamp(self.valid_until),
            entityID=self.entity_id,
        )
