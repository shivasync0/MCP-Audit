"""Database models for the Phase 3 Enterprise Control Plane."""

from sqlalchemy import Column, String, Float, DateTime, JSON, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime, timezone
import enum

Base = declarative_base()

class OrgTier(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class Organization(Base):
    __tablename__ = "organizations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    tier = Column(SQLEnum(OrgTier), default=OrgTier.FREE)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    servers = relationship("ServerRecord", back_populates="organization")

class ServerRecord(Base):
    """Database representation of an MCP Server scan target."""
    __tablename__ = "servers"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    name = Column(String, nullable=False)
    version = Column(String, nullable=False)
    publisher = Column(String, nullable=True)
    
    # Latest Risk Scores
    security_risk = Column(Float, nullable=True)
    trust_score = Column(Float, nullable=True)
    exposure_score = Column(Float, nullable=True)
    operational_risk = Column(Float, nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_scanned = Column(DateTime, nullable=True)
    
    organization = relationship("Organization", back_populates="servers")
    findings = relationship("FindingRecord", back_populates="server")

class FindingRecord(Base):
    """Database representation of a security finding."""
    __tablename__ = "findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    server_id = Column(UUID(as_uuid=True), ForeignKey("servers.id"))
    tool_id = Column(String, nullable=True) # UUID string of the tool from mcp.json
    
    rule_id = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    status = Column(String, default="open") # open, mitigated, false_positive
    
    title = Column(String, nullable=False)
    evidence = Column(String, nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)
    
    server = relationship("ServerRecord", back_populates="findings")
