from celery import Celery
from celery.schedules import crontab

from app.config import settings

celery_app = Celery(
    "threatradar",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.data_sync"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

celery_app.conf.beat_schedule = {
    "sync-nvd-cves": {
        "task": "app.tasks.data_sync.sync_nvd_cves",
        "schedule": crontab(minute=0, hour="*/6"),  # every 6h
    },
    "sync-epss-scores": {
        "task": "app.tasks.data_sync.sync_epss_scores",
        "schedule": crontab(minute=0, hour="*/12"),  # every 12h
    },
    "sync-kev-lists": {
        "task": "app.tasks.data_sync.sync_kev_lists",
        "schedule": crontab(minute=30, hour="*/6"),  # every 6h, offset 30min
    },
    "recalculate-scores": {
        "task": "app.tasks.data_sync.recalculate_scores",
        "schedule": crontab(minute=0),  # every 1h
    },
}
