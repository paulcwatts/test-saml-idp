from saml_idp.utils import inflate_and_decode

REQUEST = (
    "fZHLbttADEX3/Qph9qNXZckmLAVG0wAp0k0eXXQTMBITDyxx1CHlPr6+slIDzSbLGdx7SBx"
    "uL34NfXSkIM5zbbI4NRFx6zvHL7V5uL+ya3PRfNgKDn0+wm7SPd/Sj4lEo50IBZ17nzzLNF"
    "C4o3B0LT3c3tRmrzoKJAnOjbijY4zd0Yl1rBQY+5hJf/pwSBZw4roxkIwzh0x0OcMdoy4bn"
    "Tm9b7Hfe1FYp2m6YBNxL+zYRNeXtXkscN3mXVna6qld2SJ/Lu1m/bGy2VOJtOo2VVbhHBWZ"
    "6JpFkbU2eZoXNs1sVt1nBaxKyDdxkWbfTfTtbCQ/GZkdscCrg9pMgcGjOAHGgQS0hbvd1xu"
    "YozAGr771vWlelcEyMERXPgyo73dPP66zz0sUiNXp7zez36/j+RymOcVwwD+eofWzI/UgI0"
    "xiCUVt9nj4cvjsu7HYb5P/t2z+Pd/eufkL"
)


def test_invalid_and_decode() -> None:
    """You can inflate and decode a real request."""
    result = inflate_and_decode(REQUEST)
    assert result.tag == "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest"
    result = inflate_and_decode(REQUEST.encode())
    assert result.tag == "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest"
