"""Protocol-level security rules (SEC-PROTO)."""

from typing import List, Any
from mcp_audit.models.core import MCPServer, Tool, Severity, Confidence, Finding
from mcp_audit.scanner.rules.base import SecurityRule

class MalformedToolSchemaRule(SecurityRule):
    """SEC-PROTO-008: Malformed tool schema."""
    
    rule_id = "SEC-PROTO-008"
    category = "Protocol"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    title = "Malformed Tool Schema"
    description = "Tool input schema is not a valid JSON Schema."
    
    def evaluate_server(self, server: MCPServer) -> List[Finding]:
        findings = []
        for tool in server.tools:
            findings.extend(self.evaluate_tool(server, tool))
        return findings
        
    def evaluate_tool(self, server: MCPServer, tool: Tool) -> List[Finding]:
        findings = []
        
        if not isinstance(tool.input_schema, dict):
            findings.append(self.create_finding(
                server,
                evidence=f"input_schema is type {type(tool.input_schema).__name__}, expected dict",
                tool=tool
            ))
            return findings
            
        # Basic check if it's a JSON Schema object
        if tool.input_schema and "type" not in tool.input_schema:
            # According to JSON schema, type is usually defined at root for objects
            if "$ref" not in tool.input_schema:
                findings.append(self.create_finding(
                    server,
                    evidence="Missing 'type' or '$ref' in root of input schema",
                    tool=tool
                ))
        return findings

class SchemaBombRule(SecurityRule):
    """SEC-PROTO-004: Schema bomb (deeply nested schema)."""
    
    rule_id = "SEC-PROTO-004"
    category = "Protocol"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    title = "Schema Bomb Detected"
    description = "Tool schema contains excessive nesting which could cause parsing denial of service."
    
    MAX_DEPTH = 10
    
    def evaluate_server(self, server: MCPServer) -> List[Finding]:
        findings = []
        for tool in server.tools:
            findings.extend(self.evaluate_tool(server, tool))
        return findings
        
    def evaluate_tool(self, server: MCPServer, tool: Tool) -> List[Finding]:
        depth = self._get_schema_depth(tool.input_schema)
        if depth > self.MAX_DEPTH:
            return [self.create_finding(
                server,
                evidence=f"Schema nesting depth {depth} exceeds maximum {self.MAX_DEPTH}",
                tool=tool
            )]
        return []
        
    def _get_schema_depth(self, schema: Any, current_depth: int = 0) -> int:
        if current_depth > self.MAX_DEPTH:
            return current_depth # Fast exit
            
        if isinstance(schema, dict):
            if not schema:
                return current_depth
            return max(self._get_schema_depth(v, current_depth + 1) for v in schema.values())
        elif isinstance(schema, list):
            if not schema:
                return current_depth
            return max(self._get_schema_depth(item, current_depth + 1) for item in schema)
        return current_depth
