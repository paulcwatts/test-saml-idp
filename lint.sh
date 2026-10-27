#!/usr/bin/env bash
set -x
set -e

uv run ruff check .
uv check --preview-features check-command
uv run ruff format --check .
