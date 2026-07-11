"""
Database Models
===============
SQLAlchemy ORM models for the CVE prediction storage layer.
"""

from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey
from sqlalchemy import JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from database import Base

class User(Base):
    """Stores user accounts for authentication."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    role = Column(String(20), default="analyst")  # admin, analyst, viewer
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    predictions = relationship("CVEPredictionRecord", back_populates="user")



class CVEPredictionRecord(Base):
    """Stores every prediction made by the system for historical tracking."""

    __tablename__ = "cve_predictions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(30), index=True, nullable=True)          # e.g. CVE-2026-12345
    description = Column(Text, nullable=False)
    risk_level = Column(String(10), nullable=False, index=True)     # HIGH, MEDIUM, LOW
    confidence = Column(Float, nullable=False)
    cvss_predicted = Column(Float, nullable=True)                   # 0.0 – 10.0
    anomalous = Column(Boolean, nullable=False, default=False)
    anomaly_score = Column(Float, nullable=True)
    source = Column(String(20), default="manual", index=True)       # manual | nvd_realtime | nvd_daily
    explanation = Column(JSON, nullable=True)                       # XAI payload
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True) # Optional link to user
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    
    user = relationship("User", back_populates="predictions")

    def to_dict(self):
        """Serialize to dictionary for API responses."""
        desc = self.description
        if desc and len(desc) > 200:
            desc = desc[:200] + "..."
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "description": desc,
            "risk_level": self.risk_level,
            "confidence": round(self.confidence, 4) if self.confidence else None,
            "cvss_predicted": round(self.cvss_predicted, 2) if self.cvss_predicted else None,
            "anomalous": self.anomalous,
            "anomaly_score": round(self.anomaly_score, 4) if self.anomaly_score else None,
            "source": self.source,
            "explanation": self.explanation,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
        }
