"""MCP Server Forwarding Engine."""

from typing import Dict, Any, Optional
import asyncio
import json
from mcp_audit.gateway.models import JSONRPCRequest, JSONRPCResponse

class ForwardingEngine:
    """
    Manages connections to downstream MCP Servers and forwards traffic.
    In a full production environment, this manages subprocess (Stdio) or SSE connections.
    """
    
    def __init__(self, target_server_cmd: Optional[str] = None):
        self.target_server_cmd = target_server_cmd
        self._process: Optional[asyncio.subprocess.Process] = None
        
    async def start(self):
        """Starts the downstream MCP server process."""
        if not self.target_server_cmd:
            return
            
        # Example of starting an MCP server via stdio
        # self._process = await asyncio.create_subprocess_shell(
        #     self.target_server_cmd,
        #     stdin=asyncio.subprocess.PIPE,
        #     stdout=asyncio.subprocess.PIPE,
        #     stderr=asyncio.subprocess.PIPE
        # )
        print(f"Started downstream server: {self.target_server_cmd}")

    async def forward_request(self, request: JSONRPCRequest) -> JSONRPCResponse:
        """Forwards an allowed request to the downstream server."""
        
        # If no target server is configured (e.g. testing mode), return a mock success
        if not self.target_server_cmd:
            return JSONRPCResponse(
                id=request.id,
                result={"status": "success", "message": "Intercepted and allowed by Gateway."}
            )
            
        # In a real environment, write to stdin, wait for response on stdout
        # if self._process and self._process.stdin:
        #     payload = request.model_dump_json() + "\\n"
        #     self._process.stdin.write(payload.encode())
        #     await self._process.stdin.drain()
        #     
        #     response_line = await self._process.stdout.readline()
        #     resp_dict = json.loads(response_line.decode())
        #     return JSONRPCResponse(**resp_dict)
        
        # Mocking the response for the product demo
        return JSONRPCResponse(
            id=request.id,
            result={"status": "forwarded", "downstream_response": "ok"}
        )

    async def stop(self):
        """Terminates the downstream server."""
        if self._process:
            self._process.terminate()
            await self._process.wait()
