from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

from fastapi import FastAPI
from sqlalchemy.orm import Session, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from app.config import AppSettings, get_settings
from app.db.session import SessionLocal
from app.integrations.peeringdb import PeeringDBClient
from app.provisioning.controller_lifecycle import (
    ControllerLifecycleGateError,
    create_controller_lifecycle_manager,
    run_controller_lifecycle_preflight,
)
from app.routes.auth import router as auth_router
from app.routes.workflow import router as workflow_router


def create_app(settings: AppSettings | None = None) -> FastAPI:
    app_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if app_settings.zt_provider.strip().lower() == "self_hosted_controller":
            lifecycle_manager = create_controller_lifecycle_manager(app_settings)
            session_factory = cast(sessionmaker[Session], app.state.session_maker)
            with session_factory() as db_session:
                try:
                    run_controller_lifecycle_preflight(
                        manager=lifecycle_manager,
                        db_session=db_session,
                        strict_fail_closed=app_settings.zt_controller_readiness_strict,
                        trigger="api_startup",
                    )
                except ControllerLifecycleGateError as exc:
                    raise RuntimeError(
                        "self-hosted controller lifecycle preflight failed during API startup"
                    ) from exc
        yield

    app = FastAPI(title="ZT-IX Controller", version="0.1.0", lifespan=lifespan)
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
    app.include_router(workflow_router)

    @app.get("/", tags=["system"], name="root")
    async def root() -> dict[str, str]:
        return {"service": "zt-ix", "status": "ok"}

    @app.get("/healthz", tags=["system"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
