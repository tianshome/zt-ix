from __future__ import annotations

import uuid

from fastapi import FastAPI, HTTPException, Request
from starlette.middleware.sessions import SessionMiddleware

from app.config import AppSettings, get_settings
from app.db.session import SessionLocal
from app.integrations.peeringdb import PeeringDBClient
from app.repositories.user_asns import UserAsnRepository
from app.repositories.user_network_access import UserNetworkAccessRepository
from app.repositories.zt_networks import ZtNetworkRepository
from app.routes.auth import router as auth_router
from app.routes.workflow import router as workflow_router

ERROR_MESSAGES: dict[str, str] = {
    "oauth_error": "Login was canceled or rejected by PeeringDB.",
    "missing_code_or_state": "Callback is missing required OAuth parameters.",
    "invalid_state": "Login session is invalid or has already been used.",
    "expired_state": "Login session expired before callback completed.",
    "invalid_nonce": "OIDC nonce validation failed for the returned identity token.",
    "upstream_auth_failure": "PeeringDB token or profile request failed.",
    "no_eligible_asn": "No eligible ASN was found for this account.",
    "local_auth_disabled": "Local login is disabled in this deployment.",
    "local_invalid_credentials": "Invalid username or password.",
    "local_credential_disabled": "This local account is disabled. Contact support.",
}


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
    app.include_router(workflow_router)

    @app.get("/", tags=["system"], name="root")
    async def root() -> dict[str, str]:
        return {"service": "zt-ix", "status": "ok"}

    @app.get("/healthz", tags=["system"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/onboarding", tags=["operator"], name="onboarding_page")
    async def onboarding(request: Request) -> dict[str, object]:
        user_id = request.session.get("user_id")
        if not isinstance(user_id, str):
            raise HTTPException(status_code=401, detail="authentication required")

        try:
            user_uuid = uuid.UUID(user_id)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="invalid session user") from exc

        with app.state.session_maker() as session:
            asn_rows = UserAsnRepository(session).list_by_user_id(user_uuid)
            network_rows = ZtNetworkRepository(session).list_active()
            network_access_repo = UserNetworkAccessRepository(session)
            restricted_network_ids = network_access_repo.list_network_ids_by_user_id(user_uuid)
            if restricted_network_ids:
                network_rows = [row for row in network_rows if row.id in restricted_network_ids]

        return {
            "status": "ready",
            "user_id": user_id,
            "eligible_asns": [
                {"asn": row.asn, "net_id": row.net_id, "net_name": row.net_name}
                for row in asn_rows
            ],
            "zt_networks": [
                {"id": row.id, "name": row.name, "description": row.description}
                for row in network_rows
            ],
        }

    @app.get("/error", tags=["system"], name="error_page")
    async def error_page(code: str = "unknown", detail: str | None = None) -> dict[str, str | None]:
        return {
            "status": "error",
            "code": code,
            "message": ERROR_MESSAGES.get(code, "Unknown error"),
            "detail": detail,
        }

    return app


app = create_app()
