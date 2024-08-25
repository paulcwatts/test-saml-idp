"""SAML IdP Router."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import urljoin

from fastapi import APIRouter, Depends
from starlette.requests import Request
from starlette.responses import Response
from starlette.templating import Jinja2Templates

from .config import Settings
from .dependencies import get_settings

template_path = Path(__file__).parent.resolve() / "templates"
templates = Jinja2Templates(directory=str(template_path))

router = APIRouter()


@router.get("/metadata.xml")
def metadata_xml(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    """Return the IdP's metadata.xml."""
    base_url = str(settings.saml_idp_base_url)
    valid_until = datetime.now(UTC) + timedelta(days=365)

    lines = [line.strip() for line in settings.saml_idp_metadata_cert.splitlines()]
    cert_data = "".join(lines[1:-1])
    context = {
        "request": request,
        "entity_id": settings.saml_idp_entity_id,
        "signon_url": urljoin(base_url, "/signin"),
        "logout_url": urljoin(base_url, "/logout"),
        "valid_until": valid_until.isoformat(),
        "cert": cert_data,
    }
    return templates.TemplateResponse(
        request,
        "metadata.xml",
        context,
        media_type="text/xml",
    )
