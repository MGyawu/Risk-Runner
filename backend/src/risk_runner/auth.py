import secrets

from fastapi import Header, HTTPException, status

from .config import settings


def _check(expected: str, authorization: str | None) -> None:
    if not expected:
        return  # auth disabled (local development)
    token = (authorization or "").removeprefix("Bearer ").strip()
    if not secrets.compare_digest(token, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing bearer token")


def require_ingest_token(authorization: str | None = Header(default=None)) -> None:
    _check(settings.ingest_token, authorization)


def require_api_token(authorization: str | None = Header(default=None)) -> None:
    _check(settings.api_token, authorization)
