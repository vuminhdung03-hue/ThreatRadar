import redis as redis_lib
import structlog
from fastapi import APIRouter
from sqlalchemy import text

from app.config import settings
from app.database import async_session_factory

logger = structlog.get_logger()
router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    """Liveness/readiness check. Returns status of DB and Redis."""
    db_status = "unreachable"
    redis_status = "unavailable"

    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        logger.error("health_db_fail", error=str(e))

    # Redis is optional locally — graceful degradation
    try:
        r = redis_lib.from_url(settings.redis_url, socket_connect_timeout=1)
        r.ping()
        r.close()
        redis_status = "ok"
    except Exception:
        pass

    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "version": "1.0.0",
        "environment": settings.environment,
        "services": {"database": db_status, "redis": redis_status},
    }
