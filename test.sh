#!/usr/bin/env bash
set -x
set -e

PYTHONPATH=src uv run pytest "$@"
