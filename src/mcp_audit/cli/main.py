"""Main entry point for MCP-Audit."""
import typer
from rich.console import Console
from rich.table import Table

from mcp_audit.parser.mcp_parser import MCPParser
from mcp_audit.scanner.engine import ScannerEngine

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
        
        # Scan the server
        findings = scanner.scan_server(server)
        
        if not findings:
            console.print("\n[bold green]✓ Scan completed - no findings.[/bold green]")
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
        
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] File not found: {target}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Error parsing or scanning:[/bold red] {str(e)}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
