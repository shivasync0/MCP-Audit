import pytest
from mcp_audit.gateway.proxy import SecurityGatewayProxy
from mcp_audit.gateway.models import JSONRPCRequest

def test_gateway_proxy_dast():
    proxy = SecurityGatewayProxy()
    
    # 1. Clean Request
    clean_req = JSONRPCRequest(
        id=1,
        method="tools/call",
        params={
            "name": "read_file",
            "arguments": {
                "path": "/var/log/syslog"
            }
        }
    )
    is_allowed, reason = proxy.inspect_request(clean_req)
    assert is_allowed is True
    
    # 2. Command Injection Request
    dirty_req = JSONRPCRequest(
        id=2,
        method="tools/call",
        params={
            "name": "read_file",
            "arguments": {
                "path": "/var/log/syslog; cat /etc/passwd"
            }
        }
    )
    is_allowed, reason = proxy.inspect_request(dirty_req)
    assert is_allowed is False
    assert "Command injection" in reason
    
    # 3. Path Traversal Request in Resource Read
    trav_req = JSONRPCRequest(
        id=3,
        method="resources/read",
        params={
            "uri": "file:///var/log/../../etc/shadow"
        }
    )
    is_allowed, reason = proxy.inspect_request(trav_req)
    assert is_allowed is False
    assert "Path traversal" in reason
