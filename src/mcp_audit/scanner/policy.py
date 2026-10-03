"""Policy Engine for MCP-Audit."""

import yaml
from pathlib import Path
from typing import List, Dict, Optional
from enum import Enum
from pydantic import BaseModel
from mcp_audit.models.core import MCPServer, Finding

class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

class RuleCondition(BaseModel):
    max_security_risk: Optional[float] = None
    max_exposure_score: Optional[float] = None
    disallowed_rules: List[str] = []
    require_approval_rules: List[str] = []

class PolicyEngine:
    """Evaluates policies against an MCP Server's risk profile."""
    
    def __init__(self, policy_file: str = ".mcp-audit-policy.yaml"):
        self.default_action = PolicyAction.ALLOW
        self.condition = RuleCondition()
        self._load_policy(policy_file)
        
    def _load_policy(self, filepath: str):
        path = Path(filepath)
        if not path.exists():
            return
            
        with open(path, "r", encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
                if not data or "policy" not in data:
                    return
                policy_data = data["policy"]
                if "default_action" in policy_data:
                    self.default_action = PolicyAction(policy_data["default_action"].upper())
                
                condition_data = policy_data.get("conditions", {})
                self.condition = RuleCondition(**condition_data)
            except Exception as e:
                print(f"Warning: Failed to load policy: {e}")
                
    def evaluate(self, server: MCPServer, findings: List[Finding]) -> PolicyAction:
        """Evaluate the server and findings against the policy."""
        
        # 1. Check DENY conditions first
        if self.condition.max_security_risk is not None and server.security_risk is not None:
            if server.security_risk > self.condition.max_security_risk:
                return PolicyAction.DENY
                
        if self.condition.max_exposure_score is not None and server.exposure_score is not None:
            if server.exposure_score > self.condition.max_exposure_score:
                return PolicyAction.DENY
                
        finding_rule_ids = {f.rule_id for f in findings}
        
        for disallowed in self.condition.disallowed_rules:
            if disallowed in finding_rule_ids:
                return PolicyAction.DENY
                
        # 2. Check REQUIRE_APPROVAL conditions
        for req_appr in self.condition.require_approval_rules:
            if req_appr in finding_rule_ids:
                return PolicyAction.REQUIRE_APPROVAL
                
        # 3. Fallback to default action
        return self.default_action

    def evaluate_tools(self, server: MCPServer, findings: List[Finding]) -> Dict[str, PolicyAction]:
        """Evaluate policy on a per-tool basis, returning a map of tool_id (as string) to PolicyAction."""
        tool_actions = {}
        
        # Initialize all tools with default action
        for tool in server.tools:
            tool_actions[str(tool.id)] = self.default_action
            
        # Override based on findings
        for finding in findings:
            if not finding.tool_id:
                continue
                
            tool_id_str = str(finding.tool_id)
            current_action = tool_actions.get(tool_id_str, self.default_action)
            
            # DENY overrides everything
            if finding.rule_id in self.condition.disallowed_rules:
                tool_actions[tool_id_str] = PolicyAction.DENY
            # REQUIRE_APPROVAL overrides ALLOW
            elif finding.rule_id in self.condition.require_approval_rules and current_action != PolicyAction.DENY:
                tool_actions[tool_id_str] = PolicyAction.REQUIRE_APPROVAL
                
        # If the whole server is denied based on score, deny all tools
        server_action = self.evaluate(server, findings)
        if server_action == PolicyAction.DENY:
            for tool_id_str in tool_actions:
                tool_actions[tool_id_str] = PolicyAction.DENY
                
        return tool_actions
