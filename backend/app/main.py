from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api import router
from app.config import settings
from app.database import async_session_factory, engine

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting_threatradar_api", environment=settings.environment)
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        logger.info("database_connection_ok")
    except Exception as e:
        logger.error("database_connection_failed", error=str(e))
    yield
    await engine.dispose()
    logger.info("threatradar_api_shutdown")


app = FastAPI(
    title="ThreatRadar API",
    description="Context-aware vulnerability prioritization for security analysts",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
