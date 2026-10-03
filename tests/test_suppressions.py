import pytest
from datetime import datetime, timezone, timedelta
from mcp_audit.models.core import Finding, Severity, Confidence
from mcp_audit.scanner.suppressions import SuppressionEngine
import yaml

def test_suppression_engine(tmp_path):
    # Create a temporary suppression file
    suppression_file = tmp_path / ".mcp-audit-suppressions.yaml"
    
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=30)
    past = now - timedelta(days=30)
    
    suppressions_data = {
        "suppressions": [
            {
                "rule": "SEC-FS-001",
                "tool": "read_file",
                "reason": "Approved file reader",
                "expires": future.isoformat()
            },
            {
                "rule": "SEC-EXEC-001",
                "reason": "Global suppression for testing",
                # no expiration
            },
            {
                "rule": "SEC-NET-001",
                "reason": "Expired suppression",
                "expires": past.isoformat()
            }
        ]
    }
    
    with open(suppression_file, "w") as f:
        yaml.dump(suppressions_data, f)
        
    engine = SuppressionEngine(str(suppression_file))
    
    # Create mock findings
    findings = [
        # Should be suppressed (matches rule and tool, not expired)
        Finding(rule_id="SEC-FS-001", tool_id="00000000-0000-0000-0000-000000000001", 
                category="Filesystem", severity=Severity.HIGH, confidence=Confidence.HIGH, 
                title="", description=""),
                
        # Should NOT be suppressed (matches rule, but tool is different)
        Finding(rule_id="SEC-FS-001", tool_id="00000000-0000-0000-0000-000000000002", 
                category="Filesystem", severity=Severity.HIGH, confidence=Confidence.HIGH, 
                title="", description=""),
                
        # Should be suppressed (matches global rule)
        Finding(rule_id="SEC-EXEC-001", tool_id="00000000-0000-0000-0000-000000000003", 
                category="Execution", severity=Severity.HIGH, confidence=Confidence.HIGH, 
                title="", description=""),
                
        # Should NOT be suppressed (rule expired)
        Finding(rule_id="SEC-NET-001", tool_id="00000000-0000-0000-0000-000000000004", 
                category="Network", severity=Severity.HIGH, confidence=Confidence.HIGH, 
                title="", description=""),
    ]
    
    tools_map = {
        "00000000-0000-0000-0000-000000000001": "read_file",
        "00000000-0000-0000-0000-000000000002": "write_file",
        "00000000-0000-0000-0000-000000000003": "run_shell",
        "00000000-0000-0000-0000-000000000004": "curl_url"
    }
    
    filtered = engine.apply(findings, tools_map)
    
    assert len(filtered) == 2
    rule_ids = [f.rule_id for f in filtered]
    assert "SEC-FS-001" in rule_ids # The write_file one
    assert "SEC-NET-001" in rule_ids # The expired one
