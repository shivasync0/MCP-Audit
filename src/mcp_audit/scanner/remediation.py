"""AI-Assisted Remediation Engine."""

from mcp_audit.models.core import Finding

class RemediationEngine:
    """Uses LLM APIs to generate dynamic remediation strategies for findings."""
    
    def __init__(self, provider: str = "mock"):
        self.provider = provider
        
    def generate_remediation(self, finding: Finding, tool_name: str) -> str:
        """Generate a remediation suggestion for a specific finding."""
        
        # In a real implementation, this would format a prompt and call Gemini/OpenAI/Anthropic.
        # For Phase 1 demo, we mock the responses based on the rule_id.
        
        if finding.rule_id == "SEC-PROTO-004":
            return (
                f"**AI Suggestion for {tool_name}**: The tool schema has excessive nesting (Schema Bomb). "
                "Refactor the `inputSchema` to use flat properties or maximum nesting depth of 3. "
                "Avoid recursive `$ref` definitions if the parser isn't capped."
            )
        elif finding.rule_id == "SEC-EXEC-001":
            return (
                f"**AI Suggestion for {tool_name}**: Arbitrary command execution detected. "
                "Instead of allowing raw shell commands, restrict the inputs to an `enum` of pre-approved "
                "safe scripts, or abstract the execution behind a rigid API."
            )
        elif finding.rule_id == "SEC-FS-001":
            return (
                f"**AI Suggestion for {tool_name}**: Arbitrary filesystem access detected. "
                "Restrict the `path` argument to a specific chroot directory (e.g., `/tmp/agent_workspace`). "
                "Enforce path normalization and reject `../` inputs at the tool level."
            )
        elif finding.rule_id == "SEC-PRMPT-002":
            return (
                f"**AI Suggestion for {tool_name}**: Sensitive data requested in prompt. "
                "Do not pass credentials through plaintext prompts. Use environment variables or a secure "
                "vault integration instead, and pass only temporary access tokens."
            )
        else:
            return (
                f"**AI Suggestion**: Review the documentation for {finding.rule_id} and ensure the tool "
                "adheres to the principle of least privilege."
            )
