"""FastAPI application for the MCP Security Gateway."""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import json
from mcp_audit.gateway.models import JSONRPCRequest
from mcp_audit.gateway.proxy import SecurityGatewayProxy
from mcp_audit.api.routers import router as api_router

app = FastAPI(title="MCP-Audit Security Gateway and Control Plane")
app.include_router(api_router)

proxy = SecurityGatewayProxy()

def configure_proxy(tool_policies: dict):
    """Dynamically configure the proxy (e.g. from the CLI)."""
    proxy.tool_policies = tool_policies

# This is a basic HTTP interceptor. In a real environment, MCP often uses stdio or SSE.
# This represents the HTTP/SSE variant of the proxy.

@app.post("/mcp/rpc")
async def intercept_rpc(request: Request):
    try:
        body = await request.json()
        rpc_req = JSONRPCRequest(**body)
    except Exception as e:
        return JSONResponse(
            status_code=400, 
            content={"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}}
        )
        
    # Inspect the payload
    is_allowed, reason = proxy.inspect_request(rpc_req)
    
    if not is_allowed:
        # Block the request and return an error directly to the agent
        error_resp = proxy.create_error_response(rpc_req.id, -32000, f"Blocked by MCP-Audit: {reason}")
        return JSONResponse(status_code=200, content=error_resp.model_dump())
        
    # If allowed, we would normally forward this to the actual MCP Server
    # For now, since this is the proxy scaffolding, we mock the forwarding
    
    # ... forwarding logic to real server ...
    
    return JSONResponse(
        status_code=200,
        content={"jsonrpc": "2.0", "id": rpc_req.id, "result": "Request forwarded and executed (mock)"}
    )
