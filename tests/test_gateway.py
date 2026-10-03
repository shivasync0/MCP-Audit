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

def test_gateway_static_policy_enforcement():
    from mcp_audit.scanner.policy import PolicyAction
    
    # Initialize proxy with a known static policy (e.g. from static scan)
    tool_policies = {
        "bad_tool": PolicyAction.DENY,
        "warn_tool": PolicyAction.REQUIRE_APPROVAL,
        "good_tool": PolicyAction.ALLOW
    }
    
    proxy = SecurityGatewayProxy(tool_policies=tool_policies)
    
    # 1. Blocked by DENY policy
    req1 = JSONRPCRequest(id=1, method="tools/call", params={"name": "bad_tool", "arguments": {}})
    is_allowed, reason = proxy.inspect_request(req1)
    assert is_allowed is False
    assert "explicitly denied" in reason
    
    # 2. Blocked by REQUIRE_APPROVAL policy
    req2 = JSONRPCRequest(id=2, method="tools/call", params={"name": "warn_tool", "arguments": {}})
    is_allowed, reason = proxy.inspect_request(req2)
    assert is_allowed is False
    assert "requires explicit approval" in reason
    
    # 3. Allowed by ALLOW policy
    req3 = JSONRPCRequest(id=3, method="tools/call", params={"name": "good_tool", "arguments": {}})
    is_allowed, reason = proxy.inspect_request(req3)
    assert is_allowed is True
