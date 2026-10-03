"""Telemetry and Audit Logging for the Security Gateway."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
from mcp_audit.gateway.models import JSONRPCRequest

class EventExporter:
    """Base class for telemetry exporters."""
    def export(self, event: Dict[str, Any]):
        raise NotImplementedError

class FileExporter(EventExporter):
    """Exports events to a local NDJSON file."""
    def __init__(self, log_dir: str = "logs", filename: str = "mcp-audit.log"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.log_file = self.log_dir / filename
        
    def export(self, event: Dict[str, Any]):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

class AuditLogger:
    """Logs security events to an audit trail in OCSF (Open Cybersecurity Schema Framework) format."""
    
    def __init__(self, exporters: Optional[List[EventExporter]] = None):
        if exporters is None:
            # Default to local file logging if no exporters provided
            self.exporters = [FileExporter()]
        else:
            self.exporters = exporters
        
    def log_event(self, action: str, reason: str, request: JSONRPCRequest, tool_name: Optional[str] = None):
        """Logs an event (ALLOW/BLOCK) formatted for SIEM ingestion."""
        
        # Format event using a simplified OCSF Security Finding schema
        event_time = int(datetime.now(timezone.utc).timestamp() * 1000)
        
        activity_id = 1 if action == "ALLOW" else 2 # 1=Allow, 2=Deny
        
        event = {
            "metadata": {
                "version": "1.0.0",
                "product": {
                    "name": "MCP-Audit Security Gateway",
                    "vendor_name": "OpenSource"
                }
            },
            "category_name": "Network Activity",
            "class_name": "Network Activity",
            "activity_id": activity_id,
            "activity_name": action,
            "time": event_time,
            "message": reason,
            "observables": [
                {"name": "rpc_method", "value": request.method},
                {"name": "request_id", "value": str(request.id)}
            ],
            "unmapped": {}
        }
        
        if tool_name:
            event["observables"].append({"name": "tool_name", "value": tool_name})
            
        # Safely extract argument keys without leaking PII/secrets
        if request.params and "arguments" in request.params:
            keys = list(request.params["arguments"].keys())
            event["unmapped"]["argument_keys"] = keys
            
        for exporter in self.exporters:
            try:
                exporter.export(event)
            except Exception as e:
                print(f"Failed to export event: {e}")
