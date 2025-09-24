#!/usr/bin/bash

set -e
set -x

# Install uv
curl -LsSf https://astral.sh/uv/0.8.22/install.sh | sh

uv sync

# Generate temporary certs
mkdir -p ssl/
openssl req  \
  -new -newkey rsa:2048 -sha256 -days 365 -nodes -x509 \
  -keyout ssl/metadata.key -out ssl/metadata.crt \
  -subj '/CN=localhost/O=Example/C=US' \
  -extensions EXT -config <( \
  printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
