from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from saml_idp import router
from saml_idp.config import settings

app = FastAPI()
app.include_router(router)

TEST_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCWreTGA9HtdNIW
qMaksmEgE9zDniIFlwBtlNJtJ+xAwkQVKoOxgbUhjXbdNdzXMpU2ns4bAM4nBy3p
C7s5/tMKqvjQJ61xXyQghI2Pf2HsI/ti18L+Ura6xUFASJCojLUEEpw95f3H5cKi
xwbYmIaRv6tJ3uMNCdd00im5h1M2e/mcNim7iCKyUuF8DdzuF0btnHJ/QZoqxU/F
CE2IfwSVUxOZcPKnmJ2oXkdW58xdiOcrY8GIuom64jOSrUwZTEDzZ0HU1wnv4zPr
FdtwKIa7R5zb4xJzaCprsFhZcB4kcPAJij4QRrMoB6bemD1evqvykPsCwO0h8xF5
KPCAo95RAgMBAAECggEAOGs2PPqTMSFLxNY/Qs3T1in5wHlGbedjbqSJwftv17Ol
wHMhymYxxzVr61pOrXkwK7p8m9nKVwy2IQuWeBm1Ncpczbv9knS4V0CqrK9aoAu9
Bf6Z8ZZQ+0/+pa5GFAZThQne3MJwKtgZ788r/g/mW050OX2ucGRd+0zx+Jj2DHD+
FqKKqBvjbIgj1cCOvT3tLss6jz93+7RV6Nzmqwe7Pwy1UxL6cuLvuAGp8QQea2ER
2Dfe4gQkpzF+7lm+iwbuhnoTP+r22Zt7B+GBDs3lSPtnPGGknHuADORtfWPPZUZT
jbyEdVPZxqs8loe71kLNKVdIMKV4iYqB05mYkutX/QKBgQDKzsUKI0qSuOM1FbAV
Rck6o5TZDzcYgJPk69BEE2HRGgxOKmrcW6TmeZRDNxh7bt8Vr/GipdquSI/JxcBz
IuZexGhRNKt9IPZ6pnw4pPx5FhzK6Dt3vje9IIuEotOepEusrggSlIWBaF1x8M41
buoJI+VFD9vds9jCEHPsCWLbswKBgQC+MwlEH0Ak4bUGJpQl99ruyhKEtByqtuLK
6GENLrutKBbUoCA0TTXXDeRREPwbs3xfXrJ3aqFxm0x52NpPb1XlNxMedzCErO69
rVXo2q99ZeXu0gWhojDOr6JIYWWFjOrtVNoU2MbjqtomuO94DbkfE4UQTekLJGsg
Pj4w3v6L6wKBgAk4xbTkTevGBG7RgaQ1/CRyc7469uJiVlc+ccXmq7f6WzziqOFE
OYdRV/CGfNKABBzUV0RyDjOGkSM3nrydhaQhgizPHE0gRpTlJRjeR6yp2L1ROgMD
3zz2UeHCFaVNCzPa5fsSTc/IkxcvP/EmDfZEb5RoWDMIjn6kiODevGQJAoGAL6dR
1wONarAyTswzqh+jdtiiMyV9WThhMj1us4LV+thkf/lumCwQJUWRws3inH4n1y0+
wbSxpmkmjBDNAcH/X2KhI6zxNwys9FENiT3hYiW5qlBsoMamO+K9Yi0k5oUcB0KP
MVHu4vPXnIQRW570ltipKiCbFvOU84skwdHdLOkCgYAUAYlro5QuoiQppjOFvmU1
6fo5nC6ao7JZkF62bnli4MDJMwsnx+GaKvQnAFd++nFrDJJzKMcTHvKQHhFhpdZk
yBWtKo2Sv3AjZEf0DUrFKjYx29K/44j8AKfxE8HdzdqJxGMhZJNoC9OoUkQfWvtE
RStleM//ZI1Gduhd3gUjTQ==
-----END PRIVATE KEY-----
"""

TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIUMgfSjchLhN6ZOvaWn+yrTaAvXS8wDQYJKoZIhvcNAQEL
BQAwMzESMBAGA1UEAwwJbG9jYWxob3N0MRAwDgYDVQQKDAdFeGFtcGxlMQswCQYD
VQQGEwJVUzAeFw0yNDEwMTcxNTIwMTZaFw0yNTEwMTcxNTIwMTZaMDMxEjAQBgNV
BAMMCWxvY2FsaG9zdDEQMA4GA1UECgwHRXhhbXBsZTELMAkGA1UEBhMCVVMwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCWreTGA9HtdNIWqMaksmEgE9zD
niIFlwBtlNJtJ+xAwkQVKoOxgbUhjXbdNdzXMpU2ns4bAM4nBy3pC7s5/tMKqvjQ
J61xXyQghI2Pf2HsI/ti18L+Ura6xUFASJCojLUEEpw95f3H5cKixwbYmIaRv6tJ
3uMNCdd00im5h1M2e/mcNim7iCKyUuF8DdzuF0btnHJ/QZoqxU/FCE2IfwSVUxOZ
cPKnmJ2oXkdW58xdiOcrY8GIuom64jOSrUwZTEDzZ0HU1wnv4zPrFdtwKIa7R5zb
4xJzaCprsFhZcB4kcPAJij4QRrMoB6bemD1evqvykPsCwO0h8xF5KPCAo95RAgMB
AAGjWTBXMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDALBgNVHQ8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFNk+V9u7fJ+KDqFSFklyq6hR6bNzMA0G
CSqGSIb3DQEBCwUAA4IBAQBn4mu/zF2gPOiF4DkJiOWz5DxSlFkhC4ByMMk5VAHK
ZriXp4BwGYPLA4wGT5ff0ejQLcLwqmfzU9Y7pphrlh+Bpb/0rqnhY3Kc1QRpmSwt
pd0v7qfvnKvLB0Sa5A8hBAeplnG1MjkkWh8Oj8LPVh9cmLtoJgYWc38fVa+n1cT3
swaAvonIHgLhLx34NyjBZvZqfPoG1V+eytnUB7gh/1kStKKn5ltSammrPCmht1wB
d+0x6qJogDPd/ycseVRXWvHDstin5ZqPhFfSZ8gCmel9n5+pFhBJ2pIfFnWPIqd9
fspnxx/P93hZM5Dq+tusNyvQihMCMZg8iEXOZnC/6jRJ
-----END CERTIFICATE-----
"""


@pytest.fixture(autouse=True)
def _init_settings() -> None:
    """Initialize settings with some reasonable defaults for testing purposes."""
    settings.saml_idp_entity_id = "http://example.com/saml"
    settings.saml_idp_metadata_cert = TEST_CERT
    settings.saml_idp_metadata_key = TEST_KEY


@pytest_asyncio.fixture
async def ac() -> AsyncIterator[AsyncClient]:
    """Provide an AsyncClient."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
