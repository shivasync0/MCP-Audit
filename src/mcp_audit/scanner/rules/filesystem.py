"""Filesystem security rules (SEC-FS)."""

from typing import List
import re
from mcp_audit.models.core import MCPServer, Tool, Severity, Confidence, Finding
from mcp_audit.scanner.rules.base import SecurityRule

class ArbitraryFilesystemAccessRule(SecurityRule):
    """SEC-FS-001: Tool allows arbitrary filesystem access."""
    
    rule_id = "SEC-FS-001"
    category = "Filesystem"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    title = "Arbitrary Filesystem Access"
    description = "Tool exposes capabilities that appear to allow arbitrary filesystem reads or writes."
    
    FS_KEYWORDS = re.compile(r'\b(read file|write file|delete file|filesystem|fs|read_file|write_file)\b', re.IGNORECASE)
    
    def evaluate_server(self, server: MCPServer) -> List[Finding]:
        findings = []
        for tool in server.tools:
            findings.extend(self.evaluate_tool(server, tool))
        return findings
        
    def evaluate_tool(self, server: MCPServer, tool: Tool) -> List[Finding]:
        findings = []
        evidence_points = []
        
        # Check tool name & description
        if self.FS_KEYWORDS.search(tool.name):
            evidence_points.append(f"Tool name '{tool.name}' indicates filesystem access.")
        if tool.description and self.FS_KEYWORDS.search(tool.description):
            evidence_points.append("Tool description mentions filesystem operations.")
            
        # Check input schema properties for unrestricted path
        if isinstance(tool.input_schema, dict) and "properties" in tool.input_schema:
            props = tool.input_schema["properties"]
            if any(k in props for k in ["path", "file_path", "filepath", "filename", "file"]):
                evidence_points.append("Tool schema accepts 'path' or 'file_path' arguments.")
                
        if evidence_points:
            findings.append(self.create_finding(
                server,
                evidence=" | ".join(evidence_points),
                tool=tool
            ))
            
        return findings
