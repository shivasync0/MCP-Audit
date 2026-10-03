"""Core data models for MCP-Audit."""

from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from uuid import UUID, uuid4
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CapabilitySource(str, Enum):
    DECLARED = "declared"
    STATIC = "static"
    OBSERVED = "observed"
    INFERRED = "inferred"


class AssetCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"


class BaseEntity(BaseModel):
    """Base for all database entities."""
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Capability(BaseModel):
    """Represents a structured capability of a tool."""
    capability_type: str  # filesystem, network, process, database, etc.
    scope: str            # e.g. path pattern or URL pattern
    access_mode: str      # read, write, execute
    source: CapabilitySource
    confidence: Confidence
    evidence: Optional[str] = None


class Asset(BaseEntity):
    """Represents a sensitive data or infrastructure asset."""
    organization_id: Optional[UUID] = None
    name: str
    asset_type: str
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    data_classification: DataClassification = DataClassification.INTERNAL
    environment: str = "development"
    owner: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)


class Tool(BaseEntity):
    """Represents an MCP Tool."""
    server_id: UUID
    name: str
    description: Optional[str] = None
    input_schema: Any = Field(default_factory=dict)
    capabilities: List[Capability] = Field(default_factory=list)
    risk_score: Optional[float] = None


class Resource(BaseEntity):
    """Represents an MCP Resource."""
    server_id: UUID
    uri: str
    name: str
    description: Optional[str] = None
    mime_type: Optional[str] = None
    access_level: str = "read"


class Prompt(BaseEntity):
    """Represents an MCP Prompt."""
    server_id: UUID
    name: str
    description: Optional[str] = None
    arguments: List[Dict[str, Any]] = Field(default_factory=list)


class MCPServer(BaseEntity):
    """Represents an MCP Server."""
    organization_id: Optional[UUID] = None
    name: str
    version: str
    publisher: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    tools: List[Tool] = Field(default_factory=list)
    resources: List[Resource] = Field(default_factory=list)
    prompts: List[Prompt] = Field(default_factory=list)
    
    # Four-score risk model
    security_risk: Optional[float] = None
    trust_score: Optional[float] = None
    exposure_score: Optional[float] = None
    operational_risk: Optional[float] = None


class Finding(BaseEntity):
    """Represents a security finding from an analysis engine."""
    organization_id: Optional[UUID] = None
    server_id: Optional[UUID] = None
    tool_id: Optional[UUID] = None
    resource_id: Optional[UUID] = None
    
    rule_id: str
    category: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    evidence: Optional[str] = None
    status: str = "open"  # open, confirmed, mitigated, resolved, false_positive
