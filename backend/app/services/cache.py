"""
Redis cache helpers.

Key patterns (from CLAUDE.md):
  nvd:cves:{date}              TTL 24h
  epss:scores:{date}           TTL 24h
  cisa:kev                     TTL 12h
  threat:score:{cve_id}:{env}  TTL 6h
  dashboard:stats:{env_id}     TTL 5min
"""

import json
from typing import Any

import structlog
from redis.asyncio import ConnectionPool, Redis

from app.config import settings

logger = structlog.get_logger()

TTL = {
    "nvd_cves": 86400,       # 24h
    "epss_scores": 86400,    # 24h
    "cisa_kev": 43200,       # 12h
    "threat_score": 21600,   # 6h
    "dashboard_stats": 300,  # 5min
}

_pool: ConnectionPool | None = None


def _client() -> Redis:
    """Return a Redis client backed by the module-level connection pool."""
    global _pool
    if _pool is None:
        _pool = ConnectionPool.from_url(settings.redis_url, decode_responses=True)
    return Redis(connection_pool=_pool)


async def cache_get(key: str) -> Any | None:
    try:
        value = await _client().get(key)
        if value is None:
            return None
        return json.loads(value)
    except Exception as e:
        logger.debug("cache_miss", key=key, reason=str(e))
        return None


async def cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        await _client().setex(key, ttl, json.dumps(value))
    except Exception as e:
        logger.debug("cache_set_failed", key=key, reason=str(e))


async def cache_delete(key: str) -> None:
    try:
        await _client().delete(key)
    except Exception as e:
        logger.debug("cache_delete_failed", key=key, reason=str(e))


# ── Convenience key builders ──────────────────────────────────────────────────

def key_nvd_cves(date: str) -> str:
    return f"nvd:cves:{date}"


def key_epss_scores(date: str) -> str:
    return f"epss:scores:{date}"


def key_cisa_kev() -> str:
    return "cisa:kev"


def key_threat_score(cve_id: str, env_id: int) -> str:
    return f"threat:score:{cve_id}:{env_id}"


def key_dashboard_stats(env_id: int | None) -> str:
    return f"dashboard:stats:{env_id or 'all'}"
