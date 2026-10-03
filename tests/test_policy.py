import pytest
from mcp_audit.models.core import MCPServer, Finding, Severity, Confidence
from mcp_audit.scanner.policy import PolicyEngine, PolicyAction
import yaml

def test_policy_engine(tmp_path):
    policy_file = tmp_path / ".mcp-audit-policy.yaml"
    
    policy_data = {
        "policy": {
            "default_action": "ALLOW",
            "conditions": {
                "max_exposure_score": 50.0,
                "disallowed_rules": ["SEC-EXEC-001"],
                "require_approval_rules": ["SEC-NET-001"]
            }
        }
    }
    
    with open(policy_file, "w") as f:
        yaml.dump(policy_data, f)
        
    engine = PolicyEngine(str(policy_file))
    
    # 1. Clean server -> ALLOW
    server1 = MCPServer(name="clean", version="1.0", exposure_score=10.0, security_risk=10.0)
    assert engine.evaluate(server1, []) == PolicyAction.ALLOW
    
    # 2. High exposure -> DENY
    server2 = MCPServer(name="exposed", version="1.0", exposure_score=60.0, security_risk=10.0)
    assert engine.evaluate(server2, []) == PolicyAction.DENY
    
    # 3. Disallowed rule -> DENY
    server3 = MCPServer(name="clean-scores-bad-rule", version="1.0", exposure_score=10.0, security_risk=10.0)
    findings = [Finding(rule_id="SEC-EXEC-001", title="", description="", category="", severity=Severity.HIGH, confidence=Confidence.HIGH)]
    assert engine.evaluate(server3, findings) == PolicyAction.DENY
    
    # 4. Require approval rule -> REQUIRE_APPROVAL
    server4 = MCPServer(name="clean-scores-warn-rule", version="1.0", exposure_score=10.0, security_risk=10.0)
    findings2 = [Finding(rule_id="SEC-NET-001", title="", description="", category="", severity=Severity.HIGH, confidence=Confidence.HIGH)]
    assert engine.evaluate(server4, findings2) == PolicyAction.REQUIRE_APPROVAL
