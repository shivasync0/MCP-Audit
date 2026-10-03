"""Security Graph construction for MCP-Audit."""

import networkx as nx
from typing import List, Dict, Any
from mcp_audit.models.core import MCPServer, Tool, Finding, Asset, AssetCriticality, DataClassification

class SecurityGraphBuilder:
    """Builds a directed graph representing the security posture of an MCP server."""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        
    def build_from_server(self, server: MCPServer, findings: List[Finding]) -> nx.DiGraph:
        """Construct a graph from a server, its tools, and associated findings."""
        self.graph.clear()
        
        # Add server node
        server_node_id = f"server:{server.id}"
        self.graph.add_node(
            server_node_id, 
            type="server", 
            name=server.name, 
            version=server.version
        )
        
        # We assume an implicit Agent node that connects to the server
        agent_node_id = "agent:default"
        self.graph.add_node(agent_node_id, type="agent", name="AI Agent")
        self.graph.add_edge(agent_node_id, server_node_id, type="connects")
        
        # Add tool nodes and edges from server
        for tool in server.tools:
            tool_node_id = f"tool:{tool.id}"
            self.graph.add_node(
                tool_node_id, 
                type="tool", 
                name=tool.name
            )
            self.graph.add_edge(server_node_id, tool_node_id, type="exposes")
            
            # Map findings to capabilities and assets for this tool
            tool_findings = [f for f in findings if f.tool_id == tool.id]
            self._map_tool_capabilities(tool_node_id, tool, tool_findings)
            
        return self.graph

    def _map_tool_capabilities(self, tool_node_id: str, tool: Tool, findings: List[Finding]):
        """Derive capabilities and assets from findings and add them to the graph."""
        
        for finding in findings:
            capability_node = None
            asset_node = None
            
            # Map specific rules to capabilities/assets
            if finding.rule_id == "SEC-EXEC-001":
                capability_node = f"cap:{tool.id}:shell"
                asset_node = f"asset:{tool.id}:system"
                
                self.graph.add_node(capability_node, type="capability", name="shell.execute")
                self.graph.add_node(asset_node, type="asset", name="Host System", criticality=AssetCriticality.HIGH.value)
                
            elif finding.rule_id == "SEC-FS-001":
                capability_node = f"cap:{tool.id}:fs"
                asset_node = f"asset:{tool.id}:filesystem"
                
                self.graph.add_node(capability_node, type="capability", name="filesystem.access")
                self.graph.add_node(asset_node, type="asset", name="Filesystem", criticality=AssetCriticality.MEDIUM.value)
                
            elif finding.rule_id == "SEC-NET-001":
                capability_node = f"cap:{tool.id}:net"
                asset_node = f"asset:{tool.id}:network"
                
                self.graph.add_node(capability_node, type="capability", name="network.outbound")
                self.graph.add_node(asset_node, type="asset", name="External Network", criticality=AssetCriticality.MEDIUM.value)
                
            elif finding.rule_id == "SEC-CRED-001":
                capability_node = f"cap:{tool.id}:cred"
                asset_node = f"asset:{tool.id}:credentials"
                
                self.graph.add_node(capability_node, type="capability", name="credential.access")
                self.graph.add_node(asset_node, type="asset", name="Credentials", criticality=AssetCriticality.CRITICAL.value)
                
            if capability_node and asset_node:
                self.graph.add_edge(tool_node_id, capability_node, type="grants")
                self.graph.add_edge(capability_node, asset_node, type="accesses")
                
    def get_attack_paths_to_critical_assets(self) -> List[List[str]]:
        """Compute paths from agent to critical assets."""
        critical_assets = [
            n for n, attr in self.graph.nodes(data=True) 
            if attr.get("type") == "asset" and attr.get("criticality") in [AssetCriticality.CRITICAL.value, AssetCriticality.HIGH.value]
        ]
        
        agent_node = "agent:default"
        attack_paths = []
        
        if agent_node not in self.graph:
            return attack_paths
            
        for target in critical_assets:
            try:
                # Find all simple paths from agent to critical asset
                paths = list(nx.all_simple_paths(self.graph, source=agent_node, target=target))
                attack_paths.extend(paths)
            except nx.NetworkXNoPath:
                continue
                
        return attack_paths
