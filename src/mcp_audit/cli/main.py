"""Main entry point for MCP-Audit."""
import typer
from rich.console import Console

app = typer.Typer(
    name="mcp-audit",
    help="Runtime security control plane for AI agents and MCP infrastructure.",
    no_args_is_help=True,
)
console = Console()

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target directory, URL, or server ID to scan"),
    baseline: str = typer.Option(None, help="Baseline JSON file for differential scanning"),
):
    """Scan an MCP server or configuration for security risks."""
    console.print(f"[bold blue]Scanning target:[/bold blue] {target}")
    if baseline:
        console.print(f"[dim]Using baseline:[/dim] {baseline}")
    console.print("[yellow]Scan completed (mock) - no findings.[/yellow]")

if __name__ == "__main__":
    app()
