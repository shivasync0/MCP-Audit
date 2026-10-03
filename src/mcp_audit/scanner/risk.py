"""Risk Engine implementing the Four-Score Risk Model."""

from typing import List, Dict
from mcp_audit.models.core import MCPServer, Finding, Severity
from mcp_audit.graph.builder import SecurityGraphBuilder

class RiskEngine:
    """Calculates Security, Trust, Exposure, and Operational risk scores."""
    
    def __init__(self):
        self.severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
        
    def calculate_scores(self, server: MCPServer, findings: List[Finding], graph_builder: SecurityGraphBuilder) -> Dict[str, float]:
        """Calculate and return the four risk scores for a server."""
        
        security_risk = self._calculate_security_risk(findings)
        trust_score = self._calculate_trust_score(server)
        exposure_score = self._calculate_exposure_score(graph_builder)
        operational_risk = self._calculate_operational_risk(security_risk)
        
        # Optionally populate the server object
        server.security_risk = security_risk
        server.trust_score = trust_score
        server.exposure_score = exposure_score
        server.operational_risk = operational_risk
        
        return {
            "security_risk": security_risk,
            "trust_score": trust_score,
            "exposure_score": exposure_score,
            "operational_risk": operational_risk
        }
        
    def _calculate_security_risk(self, findings: List[Finding]) -> float:
        """Based on finding severity weights."""
        if not findings:
            return 0.0
            
        score = sum(self.severity_weights.get(f.severity, 0) for f in findings)
        # Cap at 100 for normalization
        return min(100.0, score * 2.5)
        
    def _calculate_trust_score(self, server: MCPServer) -> float:
        """Based on publisher, version, provenance. Mocked for static analysis phase."""
        score = 50.0  # Base neutral trust
        if server.publisher:
            score += 20.0
        if server.version and server.version != "0.0.0":
            score += 10.0
        return min(100.0, score)
        
    def _calculate_exposure_score(self, graph_builder: SecurityGraphBuilder) -> float:
        """Based on attack paths to critical assets in the security graph."""
        attack_paths = graph_builder.get_attack_paths_to_critical_assets()
        
        score = 0.0
        score += len(attack_paths) * 15.0  # High penalty for each distinct attack path
        
        # Check for toxic combinations (e.g. credential + network on same tool)
        toxic_combo = False
        graph = graph_builder.graph
        for node, attr in graph.nodes(data=True):
            if attr.get("type") == "tool":
                # Find granted capabilities
                caps = [v for u, v, d in graph.edges(data=True) if u == node and d.get("type") == "grants"]
                cap_names = [graph.nodes[c].get("name") for c in caps]
                if "credential.access" in cap_names and "network.outbound" in cap_names:
                    toxic_combo = True
                    break
                if "shell.execute" in cap_names and "network.outbound" in cap_names:
                    toxic_combo = True
                    break
                    
        if toxic_combo:
            score += 40.0
            
        return min(100.0, score)
        
    def _calculate_operational_risk(self, security_risk: float) -> float:
        """Based on runtime and environmental factors. Mocked for static phase."""
        # Assume development environment for now (multiplier 0.5)
        env_factor = 0.5 
        return min(100.0, security_risk * env_factor)
