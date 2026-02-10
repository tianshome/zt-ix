"""Celery task wiring for provisioning."""

from __future__ import annotations

import uuid

from celery import Celery  # type: ignore[import-untyped]

from app.config import AppSettings, get_settings
from app.provisioning.service import process_join_request_provisioning

PROVISION_JOIN_REQUEST_TASK_NAME = "zt_ix.provision_join_request"
celery_app = Celery("zt_ix")


def configure_celery(settings: AppSettings) -> None:
    celery_app.conf.broker_url = settings.redis_url
    celery_app.conf.result_backend = None
    celery_app.conf.task_ignore_result = True
    celery_app.conf.task_serializer = "json"
    celery_app.conf.accept_content = ["json"]


@celery_app.task(name=PROVISION_JOIN_REQUEST_TASK_NAME)  # type: ignore[misc]
def provision_join_request_task(request_id: str) -> None:
    settings = get_settings()
    configure_celery(settings)
    process_join_request_provisioning(
        request_id=uuid.UUID(request_id),
        settings=settings,
    )


def enqueue_provision_join_request(
    *,
    request_id: uuid.UUID,
    settings: AppSettings,
) -> None:
    configure_celery(settings)
    provision_join_request_task.delay(str(request_id))
