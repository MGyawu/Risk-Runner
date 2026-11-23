"""Risk Runner - business-aware ASPM."""


def main() -> None:
    import uvicorn

    from .config import settings

    uvicorn.run("risk_runner.app:app", host=settings.host, port=settings.port)
