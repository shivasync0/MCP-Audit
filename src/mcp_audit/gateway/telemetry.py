"""Telemetry and Audit Logging for the Security Gateway."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from mcp_audit.gateway.models import JSONRPCRequest

class AuditLogger:
    """Logs security events to an audit trail."""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.log_file = self.log_dir / "mcp-audit.log"
        
    def log_event(self, action: str, reason: str, request: JSONRPCRequest, tool_name: Optional[str] = None):
        """Logs an event (ALLOW/BLOCK) to the audit log."""
        
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "reason": reason,
            "method": request.method,
            "request_id": request.id
        }
        
        if tool_name:
            event["tool"] = tool_name
            
        # In a real environment, you wouldn't log raw arguments to avoid logging PII/Secrets, 
        # but for demonstration we log the argument keys.
        if request.params and "arguments" in request.params:
            event["argument_keys"] = list(request.params["arguments"].keys())
            
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
