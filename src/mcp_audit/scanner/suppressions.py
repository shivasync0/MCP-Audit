"""Suppression system for MCP-Audit."""

import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, ValidationError
from mcp_audit.models.core import Finding

class SuppressionRule(BaseModel):
    rule: str
    tool: Optional[str] = None
    server: Optional[str] = None
    reason: str
    expires: Optional[datetime] = None

class SuppressionEngine:
    """Handles loading and applying suppression rules."""
    
    def __init__(self, suppression_file: str = ".mcp-audit-suppressions.yaml"):
        self.suppressions: List[SuppressionRule] = []
        self._load_suppressions(suppression_file)
        
    def _load_suppressions(self, filepath: str):
        path = Path(filepath)
        if not path.exists():
            return
            
        with open(path, "r", encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
                if not data or "suppressions" not in data:
                    return
                for s in data["suppressions"]:
                    # Convert date strings to datetime if necessary
                    if "expires" in s and isinstance(s["expires"], str):
                        s["expires"] = datetime.fromisoformat(s["expires"]).replace(tzinfo=timezone.utc)
                    self.suppressions.append(SuppressionRule(**s))
            except (yaml.YAMLError, ValidationError, ValueError) as e:
                # In production, we'd log this, but for now we raise or print
                print(f"Warning: Failed to load suppressions: {e}")
                
    def apply(self, findings: List[Finding], tools_map: Dict[str, str]) -> List[Finding]:
        """Apply suppressions to a list of findings. Returns only unsuppressed findings.
        
        Args:
            findings: The raw findings from the scanner.
            tools_map: Dictionary mapping tool UUIDs to tool names for suppression matching.
        """
        filtered_findings = []
        now = datetime.now(timezone.utc)
        
        for finding in findings:
            suppressed = False
            tool_name = tools_map.get(str(finding.tool_id)) if finding.tool_id else None
            
            for supp in self.suppressions:
                # Check expiration
                if supp.expires and supp.expires < now:
                    continue
                    
                # Match rule
                if supp.rule != finding.rule_id:
                    continue
                    
                # If tool specified, it must match
                if supp.tool and supp.tool != tool_name:
                    continue
                    
                # If we get here, the rule matched
                suppressed = True
                break
                
            if not suppressed:
                filtered_findings.append(finding)
                
        return filtered_findings
