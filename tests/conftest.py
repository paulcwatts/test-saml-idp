from collections.abc import AsyncIterator

import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from saml_idp import router

app = FastAPI()
app.include_router(router)


@pytest_asyncio.fixture
async def ac() -> AsyncIterator[AsyncClient]:
    """Provide an AsyncClient."""
    transport = ASGITransport(app=app)  # pyright: ignore [reportArgumentType]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
