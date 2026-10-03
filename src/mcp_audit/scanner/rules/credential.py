"""Credential access security rules (SEC-CRED)."""

from typing import List
import re
from mcp_audit.models.core import MCPServer, Tool, Severity, Confidence, Finding
from mcp_audit.scanner.rules.base import SecurityRule

class CredentialAccessRule(SecurityRule):
    """SEC-CRED-001: Tool handles sensitive credentials."""
    
    rule_id = "SEC-CRED-001"
    category = "Credential"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    title = "Credential Access/Handling"
    description = "Tool exposes capabilities that explicitly require or handle sensitive credentials."
    
    CRED_KEYWORDS = re.compile(r'\b(password|secret|api_key|token|credential|jwt|auth)\b', re.IGNORECASE)
    
    def evaluate_server(self, server: MCPServer) -> List[Finding]:
        findings = []
        for tool in server.tools:
            findings.extend(self.evaluate_tool(server, tool))
        return findings
        
    def evaluate_tool(self, server: MCPServer, tool: Tool) -> List[Finding]:
        findings = []
        evidence_points = []
        
        # Check tool name & description
        if self.CRED_KEYWORDS.search(tool.name):
            evidence_points.append(f"Tool name '{tool.name}' suggests credential handling.")
        if tool.description and self.CRED_KEYWORDS.search(tool.description):
            evidence_points.append("Tool description mentions credentials, keys, or tokens.")
            
        # Check input schema properties
        if isinstance(tool.input_schema, dict) and "properties" in tool.input_schema:
            props = tool.input_schema["properties"]
            if any(k in props for k in ["password", "secret", "api_key", "token", "credentials"]):
                evidence_points.append("Tool schema explicitly accepts credentials as arguments.")
                
        if evidence_points:
            findings.append(self.create_finding(
                server,
                evidence=" | ".join(evidence_points),
                tool=tool
            ))
            
        return findings
