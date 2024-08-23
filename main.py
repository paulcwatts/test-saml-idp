"""Main entry point for FastAPI app."""

from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def root() -> dict[str, str]:
    """Root endpoint."""
    return {"Hello": "World"}
