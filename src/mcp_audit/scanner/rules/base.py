"""Base classes for MCP-Audit security rules."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from mcp_audit.models.core import Finding, MCPServer, Tool, Severity, Confidence

class SecurityRule(ABC):
    """Base class for all static analysis security rules."""
    
    rule_id: str
    category: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    
    # Metadata fields from TDD/Addendum
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    mitre_atlas: Optional[str] = None
    
    @abstractmethod
    def evaluate_server(self, server: MCPServer) -> List[Finding]:
        """Evaluate the entire server object and return a list of findings."""
        pass
        
    def evaluate_tool(self, server: MCPServer, tool: Tool) -> List[Finding]:
        """Evaluate a specific tool (can be overridden by tool-specific rules)."""
        return []
        
    def create_finding(
        self,
        server: MCPServer,
        evidence: str,
        tool: Optional[Tool] = None,
        override_severity: Optional[Severity] = None
    ) -> Finding:
        """Helper to construct a finding object from this rule."""
        return Finding(
            organization_id=server.organization_id,
            server_id=server.id,
            tool_id=tool.id if tool else None,
            rule_id=self.rule_id,
            category=self.category,
            severity=override_severity or self.severity,
            confidence=self.confidence,
            title=self.title,
            description=self.description,
            evidence=evidence
        )
