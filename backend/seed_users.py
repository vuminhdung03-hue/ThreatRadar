"""Seed 3 test users. Safe to re-run — uses ON CONFLICT DO NOTHING."""
import asyncio

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.config import settings
from app.services.auth import hash_password

USERS = [
    {
        "email": "admin@threatradar.com",
        "password": "admin123",
        "role": "admin",
        "environment_id": None,
    },
    {
        "email": "healthcare@threatradar.com",
        "password": "health123",
        "role": "analyst",
        "environment_id": 1,
    },
    {
        "email": "finance@threatradar.com",
        "password": "finance123",
        "role": "analyst",
        "environment_id": 3,
    },
]


async def seed():
    engine = create_async_engine(settings.async_database_url)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with factory() as session:
        for u in USERS:
            await session.execute(
                text("""
                    INSERT INTO users (email, hashed_password, role, environment_id)
                    VALUES (:email, :hashed_password, :role, :environment_id)
                    ON CONFLICT (email) DO NOTHING
                """),
                {
                    "email": u["email"],
                    "hashed_password": hash_password(u["password"]),
                    "role": u["role"],
                    "environment_id": u["environment_id"],
                },
            )
            print(f"  seeded: {u['email']}  role={u['role']}  env_id={u['environment_id']}")
        await session.commit()

    await engine.dispose()
    print("Done.")


if __name__ == "__main__":
    asyncio.run(seed())
