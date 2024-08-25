# Test SAML IdP

This is a very simple SAML Identity Provider (IdP) you can use to test your SAML
Service Provider (SP) implementation with. It's very basic right now, it allows
you to login and respond with a signed SAML response. It also supports SAML Logout.

**This is not intended to be, nor will it ever be, a fully functional
SAML IdP implementation.** It's only meant to stand up as a quick test IdP
for use in manual or automated testing.

# TODO: Configuration

There are three things you need to configure:

1. The base URL used by the server;
1. The SAML key and certificate used to sign the response;
2. The list of username/passwords that are considered valid.

# TODO: Setup

# TODO: Create a metadata certificate for development

```bash
openssl req  -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -keyout metadata.key -out metadata.crt
```


# TODO: Docker

# TODO: Development
