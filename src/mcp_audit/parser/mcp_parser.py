"""MCP Parser module for MCP-Audit."""

import json
from pathlib import Path
from typing import Dict, Any, List
from uuid import uuid4
from mcp_audit.models.core import MCPServer, Tool, Resource, Prompt

class MCPParser:
    """Parses MCP server configurations and schemas into security models."""
    
    def parse_server_config(self, config_path: str) -> MCPServer:
        """Parses an MCP configuration file (like server.json or mcp.json)."""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        # Basic server parsing
        server = MCPServer(
            id=uuid4(),
            name=data.get("name", "unknown_server"),
            version=data.get("version", "0.0.0"),
            description=data.get("description", ""),
            publisher=data.get("publisher"),
        )
        
        # Parse tools
        if "tools" in data:
            server.tools = self._parse_tools(server.id, data["tools"])
            
        # Parse resources
        if "resources" in data:
            server.resources = self._parse_resources(server.id, data["resources"])
            
        # Parse prompts
        if "prompts" in data:
            server.prompts = self._parse_prompts(server.id, data["prompts"])
            
        return server
        
    def _parse_tools(self, server_id, tools_data: List[Dict[str, Any]]) -> List[Tool]:
        tools = []
        for t_data in tools_data:
            tool = Tool(
                server_id=server_id,
                name=t_data.get("name", "unnamed_tool"),
                description=t_data.get("description", ""),
                input_schema=t_data.get("inputSchema", {})
            )
            # Future: Call capability extractor here to populate tool.capabilities
            tools.append(tool)
        return tools

    def _parse_resources(self, server_id, resources_data: List[Dict[str, Any]]) -> List[Resource]:
        resources = []
        for r_data in resources_data:
            resource = Resource(
                server_id=server_id,
                uri=r_data.get("uri", ""),
                name=r_data.get("name", ""),
                description=r_data.get("description", ""),
                mime_type=r_data.get("mimeType")
            )
            resources.append(resource)
        return resources

    def _parse_prompts(self, server_id, prompts_data: List[Dict[str, Any]]) -> List[Prompt]:
        prompts = []
        for p_data in prompts_data:
            prompt = Prompt(
                server_id=server_id,
                name=p_data.get("name", ""),
                description=p_data.get("description", ""),
                arguments=p_data.get("arguments", [])
            )
            prompts.append(prompt)
        return prompts
