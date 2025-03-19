FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder
LABEL maintainer="paulcwatts@gmail.com"

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
       uv sync --frozen --no-install-project

ADD . /app
RUN --mount=type=cache,target=/root/.cache/uv \
       uv sync --frozen --no-install-project

# Final image
FROM python:3.13-slim-bookworm

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

# Copy the application from the builder
COPY --from=builder --chown=app:app /app /app

EXPOSE 8000
ENV PYTHONPATH=/app/src
# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"
CMD ["fastapi", "run"]
