"""Prompt-specific security rules (SEC-PRMPT)."""

from typing import List
import re
from mcp_audit.models.core import MCPServer, Prompt, Severity, Confidence, Finding
from mcp_audit.scanner.rules.base import SecurityRule

class PromptInjectionRiskRule(SecurityRule):
    """SEC-PRMPT-001: Prompt accepts unbounded user input that may lead to injection."""
    
    rule_id = "SEC-PRMPT-001"
    category = "Prompt Security"
    severity = Severity.MEDIUM
    confidence = Confidence.LOW
    title = "Potential Prompt Injection Surface"
    description = "Prompt accepts string arguments without clear constraints, increasing prompt injection risk."
    
    def evaluate_server(self, server: MCPServer) -> List[Finding]:
        findings = []
        for prompt in server.prompts:
            findings.extend(self.evaluate_prompt(server, prompt))
        return findings
        
    def evaluate_prompt(self, server: MCPServer, prompt: Prompt) -> List[Finding]:
        findings = []
        
        unbounded_args = []
        for arg in prompt.arguments:
            # If it's a string, is required, and has no max length or enum constraints
            if isinstance(arg, dict):
                arg_type = arg.get("type", "string")
                if arg_type == "string" and "enum" not in arg and "maxLength" not in arg:
                    unbounded_args.append(arg.get("name", "unknown_arg"))
                    
        if unbounded_args:
            findings.append(Finding(
                organization_id=server.organization_id,
                server_id=server.id,
                rule_id=self.rule_id,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                title=self.title,
                description=self.description,
                evidence=f"Prompt '{prompt.name}' accepts unbounded string arguments: {', '.join(unbounded_args)}"
            ))
            
        return findings

class SensitiveDataPromptRule(SecurityRule):
    """SEC-PRMPT-002: Prompt inherently requests or handles sensitive data."""
    
    rule_id = "SEC-PRMPT-002"
    category = "Prompt Security"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    title = "Sensitive Data in Prompt"
    description = "Prompt name, description, or arguments indicate handling of PII or credentials."
    
    SENSITIVE_KEYWORDS = re.compile(r'\b(password|secret|api_key|token|ssn|credit_card|pii)\b', re.IGNORECASE)
    
    def evaluate_server(self, server: MCPServer) -> List[Finding]:
        findings = []
        for prompt in server.prompts:
            findings.extend(self.evaluate_prompt(server, prompt))
        return findings
        
    def evaluate_prompt(self, server: MCPServer, prompt: Prompt) -> List[Finding]:
        findings = []
        evidence_points = []
        
        if self.SENSITIVE_KEYWORDS.search(prompt.name):
            evidence_points.append(f"Prompt name '{prompt.name}' suggests sensitive data.")
            
        if prompt.description and self.SENSITIVE_KEYWORDS.search(prompt.description):
            evidence_points.append("Prompt description mentions sensitive data.")
            
        for arg in prompt.arguments:
            if isinstance(arg, dict) and "name" in arg:
                if self.SENSITIVE_KEYWORDS.search(arg["name"]):
                    evidence_points.append(f"Argument '{arg['name']}' requests sensitive data.")
                    
        if evidence_points:
            findings.append(Finding(
                organization_id=server.organization_id,
                server_id=server.id,
                rule_id=self.rule_id,
                category=self.category,
                severity=self.severity,
                confidence=self.confidence,
                title=self.title,
                description=self.description,
                evidence=" | ".join(evidence_points)
            ))
            
        return findings
