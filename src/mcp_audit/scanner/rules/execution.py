"""Execution and Shell security rules (SEC-EXEC)."""

from typing import List
import re
from mcp_audit.models.core import MCPServer, Tool, Severity, Confidence, Finding
from mcp_audit.scanner.rules.base import SecurityRule

class ShellExecutionRule(SecurityRule):
    """SEC-EXEC-001: Tool allows shell or arbitrary command execution."""
    
    rule_id = "SEC-EXEC-001"
    category = "Execution"
    severity = Severity.CRITICAL
    confidence = Confidence.MEDIUM
    title = "Arbitrary Command Execution"
    description = "Tool exposes capabilities that appear to allow arbitrary shell or command execution."
    
    # Simple heuristics for static semantic analysis
    DANGEROUS_KEYWORDS = re.compile(r'\b(shell|bash|cmd|powershell|exec|execute command|run command)\b', re.IGNORECASE)
    
    def evaluate_server(self, server: MCPServer) -> List[Finding]:
        findings = []
        for tool in server.tools:
            findings.extend(self.evaluate_tool(server, tool))
        return findings
        
    def evaluate_tool(self, server: MCPServer, tool: Tool) -> List[Finding]:
        findings = []
        evidence_points = []
        
        # Check tool name
        if self.DANGEROUS_KEYWORDS.search(tool.name):
            evidence_points.append(f"Tool name '{tool.name}' suggests execution capability.")
            
        # Check description
        if tool.description and self.DANGEROUS_KEYWORDS.search(tool.description):
            evidence_points.append("Tool description mentions shell/command execution.")
            
        # Check input schema properties
        if isinstance(tool.input_schema, dict) and "properties" in tool.input_schema:
            props = tool.input_schema["properties"]
            if any(k in props for k in ["command", "cmd", "script", "args", "executable"]):
                evidence_points.append("Tool schema accepts 'command', 'script', or 'executable' arguments.")
                
        if evidence_points:
            findings.append(self.create_finding(
                server,
                evidence=" | ".join(evidence_points),
                tool=tool
            ))
            
        return findings
