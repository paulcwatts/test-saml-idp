"""Utilities for encoding and creating SAML requests/responses."""

import base64
import zlib
from datetime import UTC, datetime, timedelta

import signxml
from lxml import etree
from lxml.builder import ElementMaker


def inflate_and_decode(data: str | bytes) -> etree.ElementTree:
    """Inflate and decode a SAML request."""
    # https://github.com/IdentityPython/pysaml2/blob/master/src/saml2/s_utils.py
    unzipped = zlib.decompress(base64.b64decode(data), -15)
    return etree.fromstring(unzipped)


def deflate_and_encode(data: str) -> bytes:
    """Deflate and encode a request."""
    return base64.b64encode(zlib.compress(data.encode())[2:-4])


def encode_response(tree: etree.ElementTree) -> str:
    """Encode a SAML response."""
    return base64.b64encode(etree.tostring(tree)).decode()


def get_elem_from_path(tree: etree.ElementTree, xpath: str) -> list[etree.Element]:
    """Get a single element from a path."""
    return tree.xpath(
        xpath,
        namespaces={
            "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
            "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
        },
        smart_strings=False,
    )


# In order for signature verification to work easily,
# the SAML assertion and XML signature namespaces have to be default
SAMLP = ElementMaker(
    namespace="urn:oasis:names:tc:SAML:2.0:protocol",
    nsmap={"saml2p": "urn:oasis:names:tc:SAML:2.0:protocol"},
)
SAML = ElementMaker(
    namespace="urn:oasis:names:tc:SAML:2.0:assertion",
    nsmap={None: "urn:oasis:names:tc:SAML:2.0:assertion"},
)
DS = ElementMaker(namespace=signxml.namespaces.ds, nsmap={None: signxml.namespaces.ds})


def saml2_timestamp(dt: datetime) -> str:
    """Format a datetime into a format acceptable by SAML2."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


CUTOFF = timedelta(minutes=10)


def is_out_of_date(dt: datetime) -> bool:
    """Return whether the issue instant is too old."""
    return (datetime.now(UTC) - dt) > CUTOFF
