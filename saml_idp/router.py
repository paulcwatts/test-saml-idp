"""SAML IdP Router."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import urljoin

from fastapi import APIRouter, Form
from lxml import etree
from starlette import status
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.templating import Jinja2Templates

from .dependencies import GetSettings, GetUser
from .metadata import SamlMetadata

template_path = Path(__file__).parent.resolve() / "templates"
templates = Jinja2Templates(directory=str(template_path))


router = APIRouter()


@router.get("/metadata.xml")
def metadata_xml(settings: GetSettings) -> Response:
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


@router.get("/")
async def main(request: Request, user: GetUser) -> Response:
    """Provide a way to show authenticated state."""
    return templates.TemplateResponse(request, "main.html", {"user": user})


@router.get("/login")
async def login(request: Request, settings: GetSettings) -> Response:
    """Provide a non-SAML login."""
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "show_users": settings.saml_idp_show_users,
            "users": settings.saml_idp_users,
        },
    )


@router.post("/login")
async def login_post(
    request: Request,
    settings: GetSettings,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    saml_request_id: Annotated[str | None, Form()] = None,
    destination: Annotated[str | None, Form()] = None,
    request_issuer: Annotated[str | None, Form()] = None,
    relay_state: Annotated[str | None, Form()] = None,
) -> Response:
    """Provide a non-SAML login."""
    # Find the user and password
    try:
        user, session_id = await settings.authenticate_user(username, password)
        # This is the SAML login
        if (
            saml_request_id is not None
            and destination is not None
            and request_issuer is not None
        ):
            pass
            # TODO: This is the SAML login
            # return redir(
            #     request,
            #     saml_request_id=saml_request_id,
            #     destination=destination,
            #     request_issuer=request_issuer,
            #     user=user,
            #     relay_state=relay_state or "",
            # )
        else:
            # This is the normal login
            # Set a cookie and redirect
            response = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
            response.set_cookie("session_id", session_id, max_age=3600)
            return response
    except ValueError as e:
        context = {
            "show_users": settings.saml_idp_show_users,
            "users": settings.saml_idp_users,
            "error_message": str(e),
            "saml_request_id": saml_request_id,
            "destination": destination,
            "request_issuer": request_issuer,
            "relay_state": relay_state,
        }
        return templates.TemplateResponse(request, "login.html", context)


@router.post("/logout-form")
async def logout_post() -> Response:
    """Provide a non-SAML login."""
    response = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("session_id")
    return response
