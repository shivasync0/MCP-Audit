"""Network security rules (SEC-NET)."""

from typing import List
import re
from mcp_audit.models.core import MCPServer, Tool, Severity, Confidence, Finding
from mcp_audit.scanner.rules.base import SecurityRule

class ArbitraryNetworkAccessRule(SecurityRule):
    """SEC-NET-001: Tool allows arbitrary outbound network access."""
    
    rule_id = "SEC-NET-001"
    category = "Network"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    title = "Arbitrary Network Access"
    description = "Tool exposes capabilities that appear to allow arbitrary outbound HTTP/network requests."
    
    NET_KEYWORDS = re.compile(r'\b(http_get|http_post|fetch|request|curl|wget|download|api_call)\b', re.IGNORECASE)
    
    def evaluate_server(self, server: MCPServer) -> List[Finding]:
        findings = []
        for tool in server.tools:
            findings.extend(self.evaluate_tool(server, tool))
        return findings
        
    def evaluate_tool(self, server: MCPServer, tool: Tool) -> List[Finding]:
        findings = []
        evidence_points = []
        
        # Check tool name & description
        if self.NET_KEYWORDS.search(tool.name):
            evidence_points.append(f"Tool name '{tool.name}' indicates network access.")
        if tool.description and self.NET_KEYWORDS.search(tool.description):
            evidence_points.append("Tool description mentions network requests.")
            
        # Check input schema properties
        if isinstance(tool.input_schema, dict) and "properties" in tool.input_schema:
            props = tool.input_schema["properties"]
            if any(k in props for k in ["url", "endpoint", "uri", "host", "domain"]):
                evidence_points.append("Tool schema accepts 'url' or 'endpoint' arguments.")
                
        if evidence_points:
            findings.append(self.create_finding(
                server,
                evidence=" | ".join(evidence_points),
                tool=tool
            ))
            
        return findings
