#!/usr/bin/env bash
set -x
set -e

uv run ruff check --fix .
uv run black .
