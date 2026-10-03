import pytest
from mcp_audit.parser.mcp_parser import MCPParser
from mcp_audit.scanner.engine import ScannerEngine
from mcp_audit.models.core import MCPServer, Tool

def test_protocol_rules():
    parser = MCPParser()
    scanner = ScannerEngine()
    
    server = parser.parse_server_config("tests/test_config.json")
    findings = scanner.scan_server(server)
    
    rule_ids = [f.rule_id for f in findings]
    assert "SEC-PROTO-008" in rule_ids, "Should detect malformed schema"
    assert "SEC-PROTO-004" in rule_ids, "Should detect schema bomb"


def test_semantic_rules():
    # Construct a mock server with tools that should trigger semantic rules
    server = MCPServer(
        name="test-server",
        version="1.0.0",
        tools=[
            Tool(
                server_id="00000000-0000-0000-0000-000000000000",
                name="execute_bash",
                description="Run arbitrary shell scripts",
                input_schema={"properties": {"command": {"type": "string"}}}
            ),
            Tool(
                server_id="00000000-0000-0000-0000-000000000000",
                name="read_file",
                description="Read a file from the filesystem",
                input_schema={"properties": {"path": {"type": "string"}}}
            ),
            Tool(
                server_id="00000000-0000-0000-0000-000000000000",
                name="fetch_url",
                description="Make an HTTP request",
                input_schema={"properties": {"endpoint": {"type": "string"}}}
            ),
            Tool(
                server_id="00000000-0000-0000-0000-000000000000",
                name="get_api_key",
                description="Retrieve sensitive API credentials",
                input_schema={"properties": {"secret": {"type": "string"}}}
            ),
        ]
    )
    
    scanner = ScannerEngine()
    findings = scanner.scan_server(server)
    rule_ids = [f.rule_id for f in findings]
    
    assert "SEC-EXEC-001" in rule_ids, "Should detect execution capability"
    assert "SEC-FS-001" in rule_ids, "Should detect filesystem capability"
    assert "SEC-NET-001" in rule_ids, "Should detect network capability"
    assert "SEC-CRED-001" in rule_ids, "Should detect credential handling capability"
