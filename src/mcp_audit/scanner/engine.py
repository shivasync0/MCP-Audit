"""Main SAST scanner engine."""

from typing import List, Type
from mcp_audit.models.core import MCPServer, Finding
from mcp_audit.scanner.rules.base import SecurityRule
from mcp_audit.scanner.rules.protocol import MalformedToolSchemaRule, SchemaBombRule
from mcp_audit.scanner.rules.execution import ShellExecutionRule
from mcp_audit.scanner.rules.filesystem import ArbitraryFilesystemAccessRule
from mcp_audit.scanner.rules.network import ArbitraryNetworkAccessRule
from mcp_audit.scanner.rules.credential import CredentialAccessRule
from mcp_audit.scanner.rules.prompts import PromptInjectionRiskRule, SensitiveDataPromptRule

class ScannerEngine:
    """Evaluates an MCP Server against a suite of security rules."""
    
    def __init__(self, custom_rules: List[Type[SecurityRule]] = None):
        # By default, load our built-in rules
        self.rules: List[SecurityRule] = []
        
        rule_classes = [
            MalformedToolSchemaRule,
            SchemaBombRule,
            ShellExecutionRule,
            ArbitraryFilesystemAccessRule,
            ArbitraryNetworkAccessRule,
            CredentialAccessRule,
            PromptInjectionRiskRule,
            SensitiveDataPromptRule,
        ]
        
        if custom_rules:
            rule_classes.extend(custom_rules)
            
        for rule_cls in rule_classes:
            self.rules.append(rule_cls())
            
    def scan_server(self, server: MCPServer) -> List[Finding]:
        """Run all loaded rules against the server and return all findings."""
        all_findings = []
        
        for rule in self.rules:
            findings = rule.evaluate_server(server)
            all_findings.extend(findings)
            
        return all_findings
