from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient, Cookies
from lxml import etree
from starlette import status

from saml_idp import Settings
from saml_idp.config import User, settings
from saml_idp.utils import deflate_and_encode, saml2_timestamp

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _set_users() -> None:
    """Add users for these tests."""
    settings.saml_idp_users = [{"username": "taylorswift", "password": "all2well"}]


@pytest.fixture
def user() -> User:
    """Return the first user."""
    assert settings.saml_idp_users
    return settings.saml_idp_users[0]


async def test_metadata_xml(ac: AsyncClient) -> None:
    """You can retrieve the metadata."""
    response = await ac.get("/metadata.xml")
    assert response.status_code == status.HTTP_200_OK
    assert "text/xml" in response.headers["content-type"]
    xml = response.content.decode()
    assert "http://example.com/saml" in xml
    assert "http://test/signin" in xml
    assert "http://test/logout" in xml

    # Make sure the metadata validates
    schema_doc = (
        Path(__file__).parent.resolve() / "schema" / "saml-schema-metadata-2.0.xsd"
    )
    with schema_doc.open("rb") as f:
        xmlschema_doc = etree.parse(f)
        schema = etree.XMLSchema(xmlschema_doc)
        schema.assertValid(etree.fromstring(xml))


async def test_metadata_xml_base_url(ac: AsyncClient) -> None:
    """You can use the base URL to change the signin/logout URLs."""
    settings.saml_idp_base_url = "https://example.com"
    response = await ac.get("/metadata.xml")
    assert response.status_code == status.HTTP_200_OK
    assert "text/xml" in response.headers["content-type"]
    xml = response.content.decode()
    assert "https://example.com/signin" in xml
    assert "https://example.com/logout" in xml


async def test_main_unauthenticated(ac: AsyncClient) -> None:
    """You can get the main page."""
    response = await ac.get("/login")
    assert response.status_code == status.HTTP_200_OK, response.content
    assert "text/html" in response.headers["content-type"]
    assert b"Sign in" in response.content


async def test_main_authenticated(ac: AsyncClient, user: User) -> None:
    """You can get the main page with a user."""
    ac.cookies = Cookies({"session_id": Settings.generate_session_id(user)})
    response = await ac.get("/")
    assert response.status_code == status.HTTP_200_OK, response.content
    assert "text/html" in response.headers["content-type"]
    assert user["username"].encode() in response.content


def request(dt: datetime | None = None) -> str:
    """Return a SAML request."""
    issue_instant = saml2_timestamp(dt or datetime.now(UTC))
    req = f"""
<saml2p:AuthnRequest
    xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    AssertionConsumerServiceURL="https://example.com/saml2/idpresponse"
    Destination="https://localhost:8000/auth/signin"
    ID="_c0bce021-ddb3-47cb-848b-b257fbbcb9f4"
    IssueInstant="{issue_instant}"
    Version="2.0"
 >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                  >http://example.com/myissuer</saml2:Issuer>
</saml2p:AuthnRequest>
"""
    return deflate_and_encode(req).decode()


@pytest.mark.parametrize("relay_state", [None, "xxxx_relay_state"])
async def test_signin_unauth(ac: AsyncClient, relay_state: str | None) -> None:
    """Not signed in should show the login page."""
    response = await ac.get(
        "/signin",
        params={"SAMLRequest": request(), "RelayState": relay_state},
    )
    assert response.status_code == status.HTTP_200_OK, response.content
    assert "text/html" in response.headers["content-type"]
    # The request ID, destination and issuer are in the HTML
    assert b"_c0bce021-ddb3-47cb-848b-b257fbbcb9f4" in response.content
    assert b"https://example.com/saml2/idpresponse" in response.content
    assert b"http://example.com/myissuer" in response.content
    assert not relay_state or relay_state.encode() in response.content


@pytest.mark.parametrize("relay_state", [None, "xxxx_relay_state"])
async def test_signin_auth(
    ac: AsyncClient,
    relay_state: str | None,
    user: User,
) -> None:
    """Signed in should redirect you back to the SP."""
    ac.cookies = Cookies({"session_id": Settings.generate_session_id(user)})
    response = await ac.get(
        "/signin",
        params={"SAMLRequest": request(), "RelayState": relay_state},
    )
    assert response.status_code == status.HTTP_200_OK, response.content
    assert "text/html" in response.headers["content-type"]
    assert b"https://example.com/saml2/idpresponse" in response.content
    assert b"SAMLResponse" in response.content
    assert not relay_state or relay_state.encode() in response.content


async def test_signin_old(ac: AsyncClient) -> None:
    """If the issue instant is too old, it is rejected."""
    dt = datetime.now(UTC) - timedelta(days=3)
    response = await ac.get("/signin", params={"SAMLRequest": request(dt)})
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.content
    assert response.content == b"Out of date"


async def test_login_get(ac: AsyncClient) -> None:
    """You can get the login page."""
    settings.saml_idp_show_users = False
    response = await ac.get("/login")
    assert response.status_code == status.HTTP_200_OK, response.content
    assert "text/html" in response.headers["content-type"]
    assert b"taylorswift" not in response.content


async def test_login_show_users(ac: AsyncClient) -> None:
    """You can show the user credentials."""
    settings.saml_idp_show_users = True
    response = await ac.get("/login")
    assert response.status_code == status.HTTP_200_OK, response.content
    assert b"taylorswift" in response.content


async def test_login_post_success_regular(ac: AsyncClient, user: User) -> None:
    """You can login without SAML."""
    response = await ac.post("/login", data=user)
    assert response.status_code == status.HTTP_302_FOUND, response.content
    assert response.cookies == {"session_id": Settings.generate_session_id(user)}


async def test_login_post_fail(ac: AsyncClient) -> None:
    """You can fail to login without SAML."""
    response = await ac.post(
        "/login",
        data={"username": "taylorswift", "password": "notpassword"},
    )
    assert response.status_code == status.HTTP_200_OK, response.content
    assert b"Invalid username or password." in response.content


@pytest.mark.parametrize("relay_state", [None, "xxxx_relay_state"])
async def test_login_post_success_saml(
    ac: AsyncClient,
    relay_state: str | None,
    user: User,
) -> None:
    """You can login with SAML."""
    response = await ac.post(
        "/login",
        data={
            "username": user["username"],
            "password": user["password"],
            "saml_request_id": "xxxx_saml_id_xxxx",
            "destination": "https://example.com/saml2/idpresponse",
            "request_issuer": "https://myissuer.com/",
            "relay_state": relay_state,
        },
    )
    assert response.status_code == status.HTTP_200_OK, response.content
    assert b"SAMLResponse" in response.content
    assert b"https://example.com/saml2/idpresponse" in response.content
    assert not relay_state or relay_state.encode() in response.content


@pytest.mark.parametrize("relay_state", [None, "xxxx_relay_state"])
async def test_login_post_fail_saml(
    ac: AsyncClient,
    relay_state: str | None,
    user: User,
) -> None:
    """You can fail to login with SAML."""
    response = await ac.post(
        "/login",
        data={
            "username": user["username"],
            "password": "notpassword",
            "saml_request_id": "xxxx_saml_id_xxxx",
            "destination": "https://example.com/saml2/idpresponse",
            "request_issuer": "https://myissuer.com/",
            "relay_state": relay_state,
        },
    )
    assert response.status_code == status.HTTP_200_OK, response.content
    assert b"Invalid username or password." in response.content
    assert b"xxxx_saml_id_xxxx" in response.content
    assert b"https://example.com/saml2/idpresponse" in response.content
    assert b"https://myissuer.com/" in response.content
    assert not relay_state or relay_state.encode() in response.content


def logout(
    issue: datetime | None = None,
    not_after: datetime | None = None,
    session_index: str = "xxxx",
) -> str:
    """Create a logout request."""
    issue = issue or datetime.now(UTC)
    not_after = not_after or issue + timedelta(minutes=5)
    issue_instant = saml2_timestamp(issue)
    not_on_or_after = saml2_timestamp(not_after)
    req = f"""
<saml2p:LogoutRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                      Destination="https://localhost:8000/auth/logout"
                      ID="_7d936c3c-0604-4660-96a6-7196e0d10989"
                      IssueInstant="{issue_instant}"
                      NotOnOrAfter="{not_on_or_after}"
                      Version="2.0"
                      >
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                  >http://myissuer.com</saml2:Issuer>
    <saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                  >davidbowie</saml2:NameID>
    <saml2p:SessionIndex>{session_index}</saml2p:SessionIndex>
</saml2p:LogoutRequest>
    """
    return deflate_and_encode(req).decode()


@pytest.mark.parametrize("relay_state", [None, "xxxx_relay_state"])
async def test_logout(ac: AsyncClient, relay_state: str | None, user: User) -> None:
    """Logout works."""
    settings.saml_idp_logout_url = "https://example.com/logout"
    ac.cookies = Cookies({"session_id": Settings.generate_session_id(user)})
    response = await ac.get(
        "/logout",
        params={"SAMLRequest": logout(), "RelayState": relay_state},
    )
    assert b"SAMLResponse" in response.content
    assert not relay_state or relay_state.encode() in response.content
    # Cookies were deleted
    assert response.cookies == Cookies([])


async def test_logout_unauth(ac: AsyncClient) -> None:
    """Logout returns request denied if not logged in."""
    settings.saml_idp_logout_url = "https://example.com/logout"
    response = await ac.get("/logout", params={"SAMLRequest": logout()})
    assert b"SAMLResponse" in response.content
    assert response.cookies == Cookies([])


async def test_logout_old(ac: AsyncClient) -> None:
    """Logout requests can be too old."""
    dt = datetime.now(UTC) - timedelta(days=3)
    response = await ac.get("/logout", params={"SAMLRequest": logout(dt)})
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.content
    assert response.content == b"Out of date"


async def test_logout_not_on_or_after(ac: AsyncClient) -> None:
    """We respect not on of after parameter."""
    issue_time = datetime.now(UTC) - timedelta(minutes=4)
    not_on_or_after = issue_time + timedelta(minutes=1)
    response = await ac.get(
        "/logout", params={"SAMLRequest": logout(issue_time, not_on_or_after)}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.content
    assert response.content == b"Out of date (not on or after)"


async def test_logout_post(ac: AsyncClient, user: User) -> None:
    """Logout a non-SAML user."""
    ac.cookies = Cookies({"session_id": Settings.generate_session_id(user)})
    response = await ac.post("/logout-form")
    assert response.status_code == status.HTTP_302_FOUND, response.content
