from typing import Dict, Any, Tuple
from mcp_audit.gateway.models import JSONRPCRequest, JSONRPCResponse
from mcp_audit.scanner.policy import PolicyAction
import re

class SecurityGatewayProxy:
    """Intercepts and inspects MCP JSON-RPC messages at runtime."""
    
    def __init__(self, tool_policies: Dict[str, PolicyAction] = None):
        self.tool_policies = tool_policies or {}
        # Basic regexes for dynamic payload inspection (DAST)
        self.COMMAND_INJECTION_PATTERN = re.compile(r'(&&|;|\|\||`|\$\(|\n)', re.IGNORECASE)
        self.PATH_TRAVERSAL_PATTERN = re.compile(r'(\.\./|\.\.\\)', re.IGNORECASE)

    def inspect_request(self, request: JSONRPCRequest) -> Tuple[bool, str]:
        """
        Inspects an incoming request. 
        Returns (is_allowed, reason).
        """
        if request.method == "tools/call":
            return self._inspect_tool_call(request)
            
        elif request.method == "resources/read":
            return self._inspect_resource_read(request)
            
        # By default, allow other methods
        return True, "Allowed"

    def _inspect_tool_call(self, request: JSONRPCRequest) -> Tuple[bool, str]:
        """Inspects parameters sent to a tool for malicious payloads and checks static policy."""
        if not request.params or "name" not in request.params:
            return False, "Missing tool name"
            
        tool_name = request.params["name"]
        
        # 1. Check static policy enforcement
        policy_action = self.tool_policies.get(tool_name, PolicyAction.ALLOW)
        if policy_action == PolicyAction.DENY:
            return False, f"Static Policy Enforcement: Tool '{tool_name}' is explicitly denied."
        elif policy_action == PolicyAction.REQUIRE_APPROVAL:
            # In a real system, this might trigger an out-of-band approval workflow (e.g. Slack/Teams)
            # For this interceptor, we block it and inform the user it needs approval.
            return False, f"Static Policy Enforcement: Tool '{tool_name}' requires explicit approval."

        # 2. Dynamic payload inspection (DAST)
        if "arguments" not in request.params:
            return True, "No arguments to inspect"
            
        args = request.params["arguments"]
        
        for key, value in args.items():
            if not isinstance(value, str):
                continue
                
            # Check for Command Injection
            if self.COMMAND_INJECTION_PATTERN.search(value):
                return False, f"Command injection payload detected in argument '{key}'"
                
            # Check for Path Traversal
            if self.PATH_TRAVERSAL_PATTERN.search(value):
                return False, f"Path traversal payload detected in argument '{key}'"
                
        return True, "Allowed"
        
    def _inspect_resource_read(self, request: JSONRPCRequest) -> Tuple[bool, str]:
        """Inspects URI requested in a resource read."""
        if not request.params or "uri" not in request.params:
            return False, "Missing URI in resource read"
            
        uri = str(request.params["uri"])
        
        # Check for Path Traversal in URI
        if self.PATH_TRAVERSAL_PATTERN.search(uri):
            return False, "Path traversal payload detected in resource URI"
            
        return True, "Allowed"
        
    def create_error_response(self, request_id: Any, code: int, message: str) -> JSONRPCResponse:
        """Helper to build a standard JSON-RPC error."""
        return JSONRPCResponse(
            id=request_id,
            error={
                "code": code,
                "message": message,
                "data": {"component": "mcp-audit-gateway"}
            }
        )
