import pytest
from starlette.requests import Request

from saml_idp.urls import rel_url_for


def test_rel_url_for_error() -> None:
    """Throw an error when there's no router."""
    req = Request({"type": "http"})
    with pytest.raises(RuntimeError, match=r"can only be used"):
        rel_url_for(req, "login")
