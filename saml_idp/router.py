"""SAML IdP Router."""

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Form, Query
from lxml import etree
from pydantic_core import Url
from starlette import status
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.templating import Jinja2Templates

from .config import Settings, User
from .dependencies import GetSettings, GetUser
from .models import (
    AuthnRequestField,
    AuthnResponse,
    LogoutRequestField,
    LogoutResponse,
    SamlMetadata,
)
from .utils import is_out_of_date

template_path = Path(__file__).parent.resolve() / "templates"
templates = Jinja2Templates(directory=str(template_path))


router = APIRouter()


@router.get("/metadata.xml")
def metadata_xml(request: Request, settings: GetSettings) -> Response:
    """Return the IdP's metadata.xml."""
    lines = [line.strip() for line in settings.saml_idp_metadata_cert.splitlines()]
    cert = "".join(lines[1:-1])

    metadata = SamlMetadata(
        entity_id=settings.saml_idp_entity_id,
        signon_url=str(request.url_for("signin")),
        logout_url=str(request.url_for("logout")),
        valid_until=datetime.now(UTC) + timedelta(days=365),
        cert=cert,
    )
    return Response(etree.tostring(metadata.to_xml()), media_type="text/xml")


@router.get("/")
async def main(request: Request, user: GetUser) -> Response:
    """Provide a way to show authenticated state."""
    return templates.TemplateResponse(request, "main.html", {"user": user})


def redir(
    request: Request,
    settings: Settings,
    *,
    saml_request_id: str,
    destination: str,
    request_issuer: str,
    user: User,
    relay_state: str,
) -> Response:
    """Render a redirect to the SP."""
    issue_instant = datetime.now(UTC)
    not_on_or_after = datetime.now(UTC) + timedelta(hours=1)
    session_id = Settings.generate_session_id(user)
    session_index = f"_{secrets.token_hex(nbytes=16)}_{session_id}"
    authn_response = AuthnResponse(
        issue_instant=issue_instant,
        issuer=Url(settings.saml_idp_entity_id),
        destination=Url(destination),
        in_response_to=saml_request_id,
        status_code="urn:oasis:names:tc:SAML:2.0:status:Success",
        subject_name_id_format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        subject_name_id=user["username"],
        subject_not_on_or_after=not_on_or_after,
        conditions_not_before=issue_instant,
        conditions_not_on_or_after=not_on_or_after,
        attributes=user.get("attributes", {}),
        audience_restriction=request_issuer,
        authn_instant=issue_instant,
        authn_context_class_ref="urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
        session_index=session_index,
    )
    context = {
        "destination": destination,
        "saml_response": authn_response.to_response(settings),
        "relay_state": relay_state,
    }
    response = templates.TemplateResponse(request, "redir.html", context)
    response.set_cookie("session_id", session_id, max_age=3600)
    return response


@router.get("/signin")
async def signin(
    request: Request,
    user: GetUser,
    settings: GetSettings,
    saml_request: Annotated[AuthnRequestField, Query(alias="SAMLRequest")],
    relay_state: Annotated[str, Query(alias="RelayState")] = "",
) -> Response:
    """Handle SAML auth requests."""
    if is_out_of_date(saml_request.issue_instant):
        # We *should* return back to the SP,
        # but we don't care and this is easier to test.
        return Response("Out of date", status_code=400)

    destination = str(saml_request.assertion_consumer_service_url)
    request_issuer = saml_request.issuer
    if user:
        return redir(
            request,
            settings,
            saml_request_id=saml_request.id,
            destination=destination,
            request_issuer=request_issuer,
            user=user,
            relay_state=relay_state,
        )

    context = {
        "show_users": settings.saml_idp_show_users,
        "users": settings.saml_idp_users,
        "saml_request_id": saml_request.id,
        "destination": destination,
        "request_issuer": request_issuer,
        "relay_state": relay_state,
    }
    return templates.TemplateResponse(request, "login.html", context)


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
            # This is the SAML login
            return redir(
                request,
                settings,
                saml_request_id=saml_request_id,
                destination=destination,
                request_issuer=request_issuer,
                user=user,
                relay_state=relay_state or "",
            )
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


@router.get("/logout", include_in_schema=False)
async def logout(
    request: Request,
    user: GetUser,
    saml_request: Annotated[LogoutRequestField, Query(alias="SAMLRequest")],
    relay_state: Annotated[str, Query(alias="RelayState")] = "",
) -> Response:
    """Handle SAML logout requests."""
    now = datetime.now(UTC)
    if is_out_of_date(saml_request.issue_instant):
        # We *should* return back to the SP,
        # but we don't care and this is easier to test.
        return Response("Out of date", status_code=400)
    if saml_request.not_on_or_after < now:
        return Response("Out of date (not on or after)", status_code=400)

    issue_instant = now
    destination = str(request.url_for("logout"))
    clear_cookie = False
    if user:
        # NOTE: Check to make sure the person logged in is the
        # one that is wanting to be logged out

        logout_response = LogoutResponse(
            issue_instant=issue_instant,
            issuer=saml_request.issuer,
            destination=Url(destination),
            in_response_to=saml_request.id,
            status_code="urn:oasis:names:tc:SAML:2.0:status:Success",
        )
        clear_cookie = True
    else:
        logout_response = LogoutResponse(
            issue_instant=issue_instant,
            issuer=saml_request.issuer,
            destination=Url(destination),
            in_response_to=saml_request.id,
            status_code="urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
        )

    context = {
        "destination": destination,
        "saml_response": logout_response.to_response(),
        "relay_state": relay_state,
    }

    response = templates.TemplateResponse(request, "redir.html", context)
    if clear_cookie:
        response.delete_cookie("session_id")
    return response


@router.post("/logout-form")
async def logout_post() -> Response:
    """Provide a non-SAML login."""
    response = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("session_id")
    return response
