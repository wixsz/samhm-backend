from collections.abc import Generator
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from app.core.config import settings
from app.db.base import Base
from app.security.password import get_password_hash


def _build_engine_kwargs(database_url: str) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "echo": settings.DB_ECHO,
        "future": True,
        "pool_pre_ping": True,
    }

    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    elif database_url.startswith("postgresql"):
        kwargs["connect_args"] = {"connect_timeout": 5}

    return kwargs


engine = create_engine(
    settings.DATABASE_URL,
    **_build_engine_kwargs(settings.DATABASE_URL),
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    future=True,
)


def initialize_database() -> None:
    # Import models before metadata creation so SQLAlchemy can register tables.
    from app.db.models import Role, RoleName, User

    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        existing_roles = {
            role.name for role in db.execute(select(Role)).scalars().all()
        }

        for role_name in RoleName:
            if role_name.value not in existing_roles:
                db.add(
                    Role(
                        name=role_name.value,
                        description=f"Default {role_name.value} role",
                    )
                )

        db.flush()

        admin_user = db.execute(
            select(User).where(User.email == settings.DEFAULT_ADMIN_EMAIL.lower())
        ).scalar_one_or_none()

        if admin_user is None:
            admin_role = db.execute(
                select(Role).where(Role.name == RoleName.ADMIN.value)
            ).scalar_one()
            db.add(
                User(
                    email=settings.DEFAULT_ADMIN_EMAIL.lower(),
                    password_hash=get_password_hash(settings.DEFAULT_ADMIN_PASSWORD),
                    full_name=settings.DEFAULT_ADMIN_NAME,
                    role_id=admin_role.id,
                )
            )

        db.commit()


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
