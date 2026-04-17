import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.environment import EnvironmentProfile
from app.models.score import ThreatScore
from app.models.threat import Threat
from app.models.user import User
from app.schemas.environment import EnvironmentCreate, EnvironmentResponse
from app.schemas.threat import ThreatListResponse, ThreatWithScore
from app.services.auth import get_current_user

logger = structlog.get_logger()
router = APIRouter(tags=["environments"])


@router.get("/environments", response_model=list[EnvironmentResponse])
async def list_environments(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(EnvironmentProfile).order_by(EnvironmentProfile.name)
    # Analysts only see their assigned environment
    if current_user.role == "analyst" and current_user.environment_id is not None:
        stmt = stmt.where(EnvironmentProfile.id == current_user.environment_id)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/environments", response_model=EnvironmentResponse, status_code=201)
async def create_environment(
    body: EnvironmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can create environments")
    env = EnvironmentProfile(
        name=body.name,
        description=body.description,
        technologies=body.technologies or [],
    )
    db.add(env)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail=f"Environment '{body.name}' already exists")

    await db.refresh(env)
    logger.info("environment_created", env_id=env.id, name=env.name, tech_count=len(body.technologies))
    return env


@router.get("/environments/{env_id}", response_model=EnvironmentResponse)
async def get_environment(env_id: int, db: AsyncSession = Depends(get_db)):
    env = await db.get(EnvironmentProfile, env_id)
    if not env:
        raise HTTPException(status_code=404, detail=f"Environment {env_id} not found")
    return env


@router.get("/environments/{env_id}/threats", response_model=ThreatListResponse)
async def get_environment_threats(
    env_id: int,
    page: int = 1,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    env = await db.get(EnvironmentProfile, env_id)
    if not env:
        raise HTTPException(status_code=404, detail=f"Environment {env_id} not found")

    join_cond = and_(ThreatScore.threat_id == Threat.cve_id, ThreatScore.environment_id == env_id)

    total = await db.scalar(
        select(func.count(Threat.cve_id)).join(ThreatScore, join_cond)
    ) or 0

    rows = (
        await db.execute(
            select(Threat, ThreatScore)
            .join(ThreatScore, join_cond)
            .order_by(ThreatScore.composite_score.desc().nullslast())
            .limit(limit)
            .offset((page - 1) * limit)
        )
    ).all()

    items: list[ThreatWithScore] = []
    for threat, score in rows:
        item = ThreatWithScore.model_validate(threat)
        item.composite_score = score.composite_score
        item.priority_level = score.priority_level
        item.tech_match_count = score.tech_match_count or 0
        item.score_breakdown = score.score_breakdown
        items.append(item)

    return ThreatListResponse(total=total, page=page, limit=limit, items=items)
