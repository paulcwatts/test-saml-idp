"""Main entry point for FastAPI app."""

from fastapi import FastAPI
from starlette.middleware.gzip import GZipMiddleware

from saml_idp import router

app = FastAPI()
app.add_middleware(GZipMiddleware)
app.include_router(router)
