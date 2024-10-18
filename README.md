# Test SAML IdP

![workflow badge](https://github.com/paulcwatts/test-saml-idp/actions/workflows/build.yml/badge.svg?branch=main)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/paulcwatts/test-saml-idp/blob/main/LICENSE)

This is a basic SAML Identity Provider (IdP) you can use to test a SAML
Service Provider (SP) implementation. It allows you to download metadata, to log in, 
and to respond with a signed SAML response. It also supports SAML Single Log Out.

**This is not intended to be, nor will it ever be, a fully functional
SAML IdP implementation.** It's only meant to stand up as a quick test IdP
for use in manual or automated testing.

# Quick Setup

The easiest way to get up and going is to use the pre-built Docker image.

## Running the server

1. Create a metadata certification for development. This will also be used
to sign SAML responses.
```bash
openssl req  -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 -keyout metadata.key -out metadata.crt
```
2. Create a `.env` file and add the following contents:
```env
SAML_IDP_ENTITY_ID=http://localhost:8000/
SAML_IDP_METADATA_CERT_FILE=/etc/saml/metadata.crt
SAML_IDP_METADATA_KEY_FILE=/etc/saml/metadata.key
SAML_IDP_USERS=[{"username": "myuser", "password": "mypass"}]
```
3. Run the Docker image:
```bash 
docker run --rm --env-file .env -p 8000:8000 \
  --read-only -v <local path to metadata.crt/key>:/etc/saml \
  paulcwatts/test-saml-idp
```
4. Go to http://localhost:8000

You can click "Sign in" and login with the credentials you provided in the 
env file. (Username: `myuser`, password: `mypass`). 

## Testing with a service provider

If you don't have a SAML Service Provider handy, you can use 
the [RSA Test Service Provider](https://sptest.iamshowcase.com/instructions#spinit)
to test that your IdP is running correctly. 

1. Download the IdP metadata from http://localhost:8000/metadata.xml:
```bash
curl http://localhost:8000/metadata.xml >metadata.xml
```
2. Go to https://sptest.iamshowcase.com/instructions#spinit and upload that file.
Copy the provided URL to the clipboard.
3. Open a browser window and paste that URL into the address bar. You should be redirected
to the Test IDP.
4. Log in using the credentials you used before (Username: `myuser`, password: `mypass`).

If everything works, you will be redirected back to the Service Provider
with the Subject Information and Authentication Details.

# Deployment

This was written so you can test your federated login functionality without having
to use an external service. To do that, you'll probably want to deploy
it on your own infrastructure. Here are some considerations you'll want to think 
about: 

1. You'll want to change the SAML entity ID to something less generic. It should be specific
to your deployment, such as the URL of the deployed service. 
2. You will want to deploy the metadata certificate and key in a secure location, 
such as [Kubernetes secrets](https://kubernetes.io/docs/concepts/configuration/secret/).
3. If you plan on supporting Single Log Out, you'll need to add a URL to which 
the service will redirect after logging out (see `SAML_IDP_LOGOUT_URL` under
[Configuration Options](#configuration-options)). 

# Configuration Options

Configuration is provided via environment variables.

| Environment Variable  | Description                                                                               | Required?           |
|-----------------------|-------------------------------------------------------------------------------------------|---------------------|
| SAML_ID_ENTITY_ID     | The Entity ID specified in the SAML IdP metadata. This must be a URL.                     | Yes                 |
| SAML_IDP_METADATA_CERT | The path to the SAML signing certificate file.                                            | Yes                 |
| SAML_IDP_METADATA_KEY | The path to the SAML signing private key file.                                            | Yes                 |                                                                
| SAML_IDP_USERS | The list of user credentials to accept                                                    | Yes                 |
| SAML_IDP_BASE_URL | The base URL to use for the signin/logout endpoints. By default, it is the base host URL. | No                  |
| SAML_IDP_LOGOUT_URL | The URL to redirect to after Single Log Out                                               | Only if SLO is used |
| SAML_IDP_SHOW_USERS | If True, display a table of credentials on the login screen. Defaults to False.           | No |
| SAML_IDP_ROUTER_PREFIX | If set, adds a prefix to all URLs. Default is empty. | No | 

## Defining Users 

You can define credentials that are accepted using the `SAML_IDP_USERS` environment 
variable. (You don't *have* to specify any users, but if you don't you can't log in
and this service isn't very useful.) The format of `SAML_IDP_USERS` is a JSON list,
with each element in the list being the following format:

```typescript
interface User {
  username: string;
  password: string;
  attributes?: Record<string, string>;
}
```

Or if you prefer, in Python:

```python
class User(TypedDict):
    username: Required[str]
    password: Required[str]
    attributes: NotRequired[dict[str, str]]
```

If `attributes` is specified, the service will include those as SAML Attributes 
in the AuthnResponse.
