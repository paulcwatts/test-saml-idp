"""Main entry point for FastAPI app."""

from fastapi import FastAPI
from starlette.middleware.gzip import GZipMiddleware

from saml_idp import router
from saml_idp.config import settings

app = FastAPI()
app.add_middleware(GZipMiddleware)
app.include_router(router, prefix=settings.saml_idp_router_prefix)
