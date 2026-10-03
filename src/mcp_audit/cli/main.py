import typer
import json
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table

from mcp_audit.parser.mcp_parser import MCPParser
from mcp_audit.scanner.engine import ScannerEngine
from mcp_audit.scanner.suppressions import SuppressionEngine
from mcp_audit.graph.builder import SecurityGraphBuilder
from mcp_audit.scanner.risk import RiskEngine
from mcp_audit.scanner.policy import PolicyEngine, PolicyAction
from mcp_audit.scanner.remediation import RemediationEngine
from rich.panel import Panel
from rich.text import Text

app = typer.Typer(
    name="mcp-audit",
    help="Runtime security control plane for AI agents and MCP infrastructure.",
    no_args_is_help=True,
)
console = Console()

@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to MCP server configuration (e.g., mcp.json)"),
    baseline: str = typer.Option(None, help="Baseline JSON file for differential scanning"),
    baseline_save: str = typer.Option(None, help="Save the current findings as a new baseline"),
    ai_remediate: bool = typer.Option(False, "--ai-remediate", help="Generate AI-assisted remediation suggestions for findings"),
):
    """Scan an MCP server configuration for security risks."""
    console.print(f"[bold blue]Scanning target:[/bold blue] {target}")
    if baseline:
        console.print(f"[dim]Using baseline:[/dim] {baseline}")
        
    parser = MCPParser()
    scanner = ScannerEngine()
    
    try:
        # Parse the configuration
        server = parser.parse_server_config(target)
        console.print(f"[green]Successfully parsed server:[/green] {server.name} (v{server.version})")
        console.print(f"  - Tools: {len(server.tools)}")
        console.print(f"  - Resources: {len(server.resources)}")
        
        # Load suppressions if any
        suppression_engine = SuppressionEngine()
        tools_map = {str(t.id): t.name for t in server.tools}
        
        # Scan the server
        raw_findings = scanner.scan_server(server)
        
        # Apply suppressions
        findings = suppression_engine.apply(raw_findings, tools_map)
        
        # Build Security Graph and Calculate Risk
        graph_builder = SecurityGraphBuilder()
        graph_builder.build_from_server(server, findings)
        
        risk_engine = RiskEngine()
        scores = risk_engine.calculate_scores(server, findings, graph_builder)
        
        # Display Risk Assessment
        risk_text = Text()
        risk_text.append(f"Security Risk:    {scores['security_risk']:>5.1f}/100\n", style="bold red" if scores['security_risk'] > 50 else "bold yellow")
        risk_text.append(f"Trust Score:      {scores['trust_score']:>5.1f}/100\n", style="bold green" if scores['trust_score'] > 50 else "bold yellow")
        risk_text.append(f"Exposure Score:   {scores['exposure_score']:>5.1f}/100\n", style="bold red" if scores['exposure_score'] > 50 else "bold yellow")
        risk_text.append(f"Operational Risk: {scores['operational_risk']:>5.1f}/100", style="bold yellow")
        
        console.print(Panel(risk_text, title="RISK ASSESSMENT", expand=False))
        
        # Evaluate Policy
        policy_engine = PolicyEngine()
        policy_decision = policy_engine.evaluate(server, findings)
        
        if policy_decision == PolicyAction.DENY:
            decision_style = "bold white on red"
        elif policy_decision == PolicyAction.REQUIRE_APPROVAL:
            decision_style = "bold black on yellow"
        else:
            decision_style = "bold white on green"
            
        console.print(f"\n[bold]Policy Decision:[/bold] [{decision_style}] {policy_decision.value} [/{decision_style}]")
        
        # Handle baseline mode
        existing_findings_count = 0
        if baseline and os.path.exists(baseline):
            with open(baseline, "r") as f:
                baseline_data = json.load(f)
                # For simplicity, we diff based on rule_id + tool name
                baseline_signatures = set()
                for bf in baseline_data.get("findings", []):
                    baseline_signatures.add(f"{bf['rule_id']}:{bf.get('tool_name', 'Server')}")
            
            new_findings = []
            for f in findings:
                tool = next((t for t in server.tools if t.id == f.tool_id), None)
                target_str = tool.name if tool else "Server"
                sig = f"{f.rule_id}:{target_str}"
                
                if sig in baseline_signatures:
                    existing_findings_count += 1
                else:
                    new_findings.append(f)
            findings = new_findings
        
        # Save baseline if requested
        if baseline_save:
            baseline_output = {"findings": []}
            for f in findings:
                tool = next((t for t in server.tools if t.id == f.tool_id), None)
                target_str = tool.name if tool else "Server"
                baseline_output["findings"].append({
                    "rule_id": f.rule_id,
                    "tool_name": target_str,
                    "severity": f.severity.value
                })
            with open(baseline_save, "w") as f:
                json.dump(baseline_output, f, indent=2)
            console.print(f"[green]Saved {len(findings)} findings to baseline {baseline_save}[/green]")
            return

        suppressed_count = len(raw_findings) - len(findings) - existing_findings_count
        if suppressed_count > 0 or existing_findings_count > 0:
            console.print(f"[dim]Filtered out {suppressed_count} suppressed and {existing_findings_count} baseline findings.[/dim]")
            
        if not findings:
            console.print("\n[bold green]Scan completed - no new findings.[/bold green]")
            return
            
        console.print(f"\n[bold red]Scan completed - {len(findings)} findings:[/bold red]")
        
        # Display findings
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Rule ID", style="cyan", width=15)
        table.add_column("Severity")
        table.add_column("Target (Tool)")
        table.add_column("Description")
        
        for f in findings:
            target_str = "Server"
            if f.tool_id:
                # Find tool name
                tool = next((t for t in server.tools if t.id == f.tool_id), None)
                target_str = f"Tool: {tool.name}" if tool else "Tool"
                
            color = "red" if f.severity in ["critical", "high"] else "yellow"
            table.add_row(
                f.rule_id,
                f"[{color}]{f.severity.upper()}[/{color}]",
                target_str,
                f.title
            )
            
        console.print(table)
        
        # Display AI Remediations if requested
        if ai_remediate and findings:
            console.print("\n[bold cyan]AI-Assisted Remediation Suggestions:[/bold cyan]")
            remediation_engine = RemediationEngine()
            for f in findings:
                tool = next((t for t in server.tools if t.id == f.tool_id), None)
                target_str = f"Tool: {tool.name}" if tool else "Server"
                suggestion = remediation_engine.generate_remediation(f, target_str)
                console.print(f"- {suggestion}")
        
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] File not found: {target}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Error parsing or scanning:[/bold red] {str(e)}")
        raise typer.Exit(code=1)

@app.command()
def proxy(
    port: int = typer.Option(8000, help="Port to run the gateway on"),
    host: str = typer.Option("127.0.0.1", help="Host to bind the gateway to")
):
    """Start the MCP-Audit Runtime Security Gateway."""
    import uvicorn
    console.print(f"[bold green]Starting Runtime Security Gateway on {host}:{port}[/bold green]")
    uvicorn.run("mcp_audit.gateway.app:app", host=host, port=port, reload=True)

if __name__ == "__main__":
    app()
