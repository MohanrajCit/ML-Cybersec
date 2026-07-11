"""
Database Configuration
======================
SQLite database for persisting CVE predictions and historical analytics.
Uses SQLAlchemy ORM with synchronous sessions.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
import logging

logger = logging.getLogger(__name__)

# SQLite database stored alongside the backend code
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///cve_predictions.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency: yields a DB session, auto-closes after use."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables if they don't exist. Safe to call multiple times."""
    from db_models import CVEPredictionRecord, User  # noqa: F401 — registers the model
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Database initialized (SQLite)")
