#!/usr/bin/env bash
set -x
set -e

uv run ruff check .
uv run pyright
uv run black --check .
