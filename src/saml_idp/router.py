"""SAML IdP Router."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import urljoin

from fastapi import APIRouter, Depends
from lxml import etree
from starlette.responses import Response
from starlette.templating import Jinja2Templates

from .config import Settings
from .dependencies import get_settings
from .metadata import SamlMetadata

template_path = Path(__file__).parent.resolve() / "templates"
templates = Jinja2Templates(directory=str(template_path))

router = APIRouter()


@router.get("/metadata.xml")
def metadata_xml(
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    """Return the IdP's metadata.xml."""
    lines = [line.strip() for line in settings.saml_idp_metadata_cert.splitlines()]
    cert = "".join(lines[1:-1])

    base_url = str(settings.saml_idp_base_url)
    metadata = SamlMetadata(
        entity_id=settings.saml_idp_entity_id,
        signon_url=urljoin(base_url, "/signin"),
        logout_url=urljoin(base_url, "/logout"),
        valid_until=datetime.now(UTC) + timedelta(days=365),
        cert=cert,
    )
    return Response(etree.tostring(metadata.to_xml()), media_type="text/xml")
