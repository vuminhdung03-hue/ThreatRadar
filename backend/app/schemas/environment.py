from datetime import datetime

from pydantic import BaseModel, Field


class EnvironmentCreate(BaseModel):
    name: str = Field(..., max_length=100, description="Unique environment name")
    description: str | None = None
    technologies: list[str] = Field(
        default_factory=list,
        description="List of vendor:product technology identifiers",
    )


class EnvironmentResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    name: str
    description: str | None
    technologies: list[str] | None
    created_at: datetime | None
