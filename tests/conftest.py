from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic_core import Url

from saml_idp import Settings, router
from saml_idp.dependencies import get_settings

app = FastAPI()
app.include_router(router)


@pytest.fixture(scope="session", autouse=True)
def settings() -> Settings:
    """Mock settings for the application."""
    path = Path(__file__).parent.resolve() / "files"

    settings = Settings(
        saml_idp_entity_id="http://localhost:8000/idp",
        saml_idp_base_url=Url("http://localhost:8000"),
        saml_idp_metadata_cert_file=str(path / "metadata.crt"),
        saml_idp_metadata_key_file=str(path / "metadata.key"),
    )

    def override_get_settings() -> Settings:
        return settings

    app.dependency_overrides[get_settings] = override_get_settings
    return settings


@pytest_asyncio.fixture
async def ac() -> AsyncIterator[AsyncClient]:
    """Provide an AsyncClient."""
    transport = ASGITransport(app=app)  # pyright: ignore [reportArgumentType]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
