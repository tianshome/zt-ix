from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from starlette.middleware.sessions import SessionMiddleware

from app.config import AppSettings, get_settings
from app.db.session import SessionLocal
from app.integrations.peeringdb import PeeringDBClient
from app.routes.auth import router as auth_router


def create_app(settings: AppSettings | None = None) -> FastAPI:
    app_settings = settings or get_settings()
    app = FastAPI(title="ZT-IX Controller", version="0.1.0")
    app.state.settings = app_settings
    app.state.session_maker = SessionLocal
    app.state.peeringdb_client = PeeringDBClient(app_settings)

    app.add_middleware(
        SessionMiddleware,
        secret_key=app_settings.app_secret_key,
        session_cookie=app_settings.session_cookie_name,
        max_age=app_settings.session_cookie_max_age_seconds,
        same_site="lax",
        https_only=app_settings.session_cookie_secure,
    )

    app.include_router(auth_router)

    @app.get("/", tags=["system"], name="root")
    async def root() -> dict[str, str]:
        return {"service": "zt-ix", "status": "ok"}

    @app.get("/healthz", tags=["system"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/onboarding", tags=["operator"], name="onboarding_page")
    async def onboarding(request: Request) -> dict[str, str]:
        user_id = request.session.get("user_id")
        if not isinstance(user_id, str):
            raise HTTPException(status_code=401, detail="authentication required")
        return {"status": "ready", "user_id": user_id}

    @app.get("/error", tags=["system"], name="error_page")
    async def error_page(code: str = "unknown") -> dict[str, str]:
        return {"status": "error", "code": code}

    return app


app = create_app()
