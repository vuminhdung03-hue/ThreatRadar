from fastapi import APIRouter

from app.api import auth, dashboard, environments, health, threats

router = APIRouter()
router.include_router(health.router)
router.include_router(auth.router, prefix="/api/v1")
router.include_router(threats.router, prefix="/api/v1")
router.include_router(environments.router, prefix="/api/v1")
router.include_router(dashboard.router, prefix="/api/v1")
