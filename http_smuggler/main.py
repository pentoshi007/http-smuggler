"""CLI interface for HTTP Smuggler.

Provides a command-line interface for scanning targets for
HTTP request smuggling vulnerabilities.
"""

import asyncio
import sys
from typing import Optional, List
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from http_smuggler.core.config import (
    ScanConfig,
    ScanMode,
    OutputFormat,
    PayloadConfig,
    ExploitConfig,
    SafetyConfig,
    CrawlConfig,
)
from http_smuggler.core.models import SmugglingVariant
from http_smuggler.core.engine import SmugglerEngine
from http_smuggler.core.exceptions import ConfigurationError, ScanAbortedError
from http_smuggler.analysis.reporter import Reporter
from http_smuggler.utils.logging import setup_logging, console


# ASCII Banner
BANNER = r"""
[bold cyan]
  _   _ _____ _____ ____    ____                              _           
 | | | |_   _|_   _|  _ \  / ___| _ __ ___  _   _  __ _  __ _| | ___ _ __ 
 | |_| | | |   | | | |_) | \___ \| '_ ` _ \| | | |/ _` |/ _` | |/ _ \ '__|
 |  _  | | |   | | |  __/   ___) | | | | | | |_| | (_| | (_| | |  __/ |   
 |_| |_| |_|   |_| |_|     |____/|_| |_| |_|\__,_|\__, |\__, |_|\___|_|   
                                                  |___/ |___/             
[/bold cyan]
[dim]HTTP Request Smuggling Detection & Exploitation Tool[/dim]
"""


def print_banner():
    """Print the tool banner."""
    console.print(BANNER)


@click.group()
@click.version_option(version="1.0.0", prog_name="http-smuggler")
def cli():
    """HTTP-Smuggler: Advanced HTTP Request Smuggling Detection Tool
    
    Detect and exploit HTTP request smuggling vulnerabilities including
    CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, H2.CRLF, and WebSocket smuggling.
    """
    pass


@cli.command()
@click.argument("target")
@click.option(
    "--mode", "-m",
    type=click.Choice(["passive", "safe", "normal", "aggressive"]),
    default="normal",
    help="Scan mode: passive (protocol only), safe (timing only), normal (timing+differential), aggressive (with exploitation)"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file for scan results"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "markdown", "text"]),
    default="json",
    help="Output format"
)
@click.option(
    "--crawl/--no-crawl",
    default=True,
    help="Enable/disable domain crawling"
)
@click.option(
    "--exploit/--no-exploit",
    default=False,
    help="Enable exploitation confirmation (aggressive mode)"
)
@click.option(
    "--depth",
    type=int,
    default=3,
    help="Maximum crawl depth"
)
@click.option(
    "--max-endpoints",
    type=int,
    default=100,
    help="Maximum endpoints to test"
)
@click.option(
    "--variants",
    type=str,
    default=None,
    help="Comma-separated list of variants to test (e.g., CL.TE,TE.CL,H2.CL)"
)
@click.option(
    "--header", "-H",
    multiple=True,
    help="Custom headers (e.g., -H 'Authorization: Bearer token')"
)
@click.option(
    "--cookie", "-c",
    type=str,
    help="Cookies to include (e.g., 'session=abc; token=xyz')"
)
@click.option(
    "--timeout",
    type=float,
    default=10.0,
    help="Request timeout in seconds"
)
@click.option(
    "--rate-limit",
    type=float,
    default=2.0,
    help="Requests per second limit"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Verbose output"
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Quiet mode (minimal output)"
)
@click.option(
    "--http2-only",
    is_flag=True,
    help="Test only HTTP/2 variants"
)
@click.option(
    "--classic-only",
    is_flag=True,
    help="Test only classic HTTP/1.1 variants"
)
def scan(
    target: str,
    mode: str,
    output: Optional[str],
    format: str,
    crawl: bool,
    exploit: bool,
    depth: int,
    max_endpoints: int,
    variants: Optional[str],
    header: tuple,
    cookie: Optional[str],
    timeout: float,
    rate_limit: float,
    verbose: bool,
    quiet: bool,
    http2_only: bool,
    classic_only: bool,
):
    """Scan TARGET for HTTP request smuggling vulnerabilities.
    
    TARGET should be a full URL (e.g., https://example.com)
    
    Examples:
    
      http-smuggler scan https://example.com
      
      http-smuggler scan https://example.com --mode aggressive --exploit
      
      http-smuggler scan https://example.com --no-crawl -o report.json
      
      http-smuggler scan https://example.com --variants CL.TE,TE.CL
    """
    if not quiet:
        print_banner()
    
    # Auto-add https:// if no scheme provided
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
        if not quiet:
            console.print(f"[dim]Note: No scheme provided, using https://[/dim]")
    
    # Validate URL
    from http_smuggler.utils.helpers import parse_url
    parsed = parse_url(target)
    if not parsed.host:
        console.print(f"[red]Error:[/red] Invalid URL: {target}")
        sys.exit(1)
    
    # Setup logging
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(level=log_level, quiet=quiet)
    
    # Parse variants
    enabled_variants = _parse_variants(variants, http2_only, classic_only)
    
    # Parse headers
    custom_headers = _parse_headers(header)
    
    # Parse cookies
    cookies = _parse_cookies(cookie)
    
    # Build configuration
    scan_mode = ScanMode(mode)
    output_format = OutputFormat(format)
    
    config = ScanConfig(
        target_url=target,
        mode=scan_mode,
        skip_crawl=not crawl,
        verbose=verbose,
        quiet=quiet,
        crawl=CrawlConfig(
            max_depth=depth,
            max_endpoints=max_endpoints,
            custom_headers=custom_headers,
            cookies=cookies,
        ),
        safety=SafetyConfig(
            timing_detection_timeout=timeout,
            requests_per_second=rate_limit,
        ),
        payload=PayloadConfig(
            enabled_variants=enabled_variants,
        ),
        exploit=ExploitConfig(
            enabled=exploit or mode == "aggressive",
        ),
        report=ReportConfig(
            format=output_format,
            output_file=output,
        ),
    )
    
    # Run scan
    try:
        result = asyncio.run(_run_scan_with_progress(config, quiet))
        
        # Generate report
        reporter = Reporter(config.report)
        report_content = reporter.generate(result, output_format)
        
        # Output
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(report_content)
            if not quiet:
                console.print(f"\n[green]Report saved to:[/green] {output}")
        else:
            if format == "json":
                console.print_json(report_content)
            else:
                console.print(report_content)
        
        # Summary
        if not quiet:
            _print_summary(result)
        
        # Exit code based on findings
        if result.vulnerabilities:
            sys.exit(1)  # Vulnerabilities found
        sys.exit(0)
        
    except ConfigurationError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(2)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if verbose:
            console.print_exception()
        sys.exit(1)


async def _run_scan_with_progress(config: ScanConfig, quiet: bool):
    """Run scan with progress display."""
    engine = SmugglerEngine(config)
    
    if quiet:
        return await engine.scan()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=100)
        
        # Run scan
        result = await engine.scan()
        
        progress.update(task, completed=100)
    
    return result


def _print_summary(result):
    """Print scan summary table."""
    console.print()
    
    # Summary table
    table = Table(title="Scan Summary", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    duration = (result.scan_end - result.scan_start).total_seconds()
    table.add_row("Target", result.target)
    table.add_row("Duration", f"{duration:.2f}s")
    table.add_row("Endpoints Tested", str(result.endpoints_tested))
    table.add_row("Vulnerabilities", str(len(result.vulnerabilities)))
    
    console.print(table)
    
    # Vulnerability details
    if result.vulnerabilities:
        console.print()
        vuln_table = Table(title="Vulnerabilities Found", box=box.ROUNDED)
        vuln_table.add_column("Variant", style="red")
        vuln_table.add_column("Endpoint", style="cyan")
        vuln_table.add_column("Confidence", style="yellow")
        vuln_table.add_column("Severity", style="magenta")
        
        for vuln in result.vulnerabilities:
            vuln_table.add_row(
                vuln.variant.value,
                vuln.endpoint[:50] + "..." if len(vuln.endpoint) > 50 else vuln.endpoint,
                f"{vuln.detection_result.confidence:.0%}",
                vuln.severity,
            )
        
        console.print(vuln_table)


def _parse_variants(
    variants_str: Optional[str],
    http2_only: bool,
    classic_only: bool,
) -> set:
    """Parse variant string into set of SmugglingVariant."""
    if http2_only:
        return {
            SmugglingVariant.H2_CL,
            SmugglingVariant.H2_TE,
            SmugglingVariant.H2_CRLF,
            SmugglingVariant.H2_TUNNEL,
        }
    
    if classic_only:
        return {
            SmugglingVariant.CL_TE,
            SmugglingVariant.TE_CL,
            SmugglingVariant.TE_TE,
        }
    
    if not variants_str:
        # Default variants
        return {
            SmugglingVariant.CL_TE,
            SmugglingVariant.TE_CL,
            SmugglingVariant.TE_TE,
            SmugglingVariant.H2_CL,
            SmugglingVariant.H2_TE,
            SmugglingVariant.H2_CRLF,
            SmugglingVariant.WS_VERSION,
        }
    
    variant_map = {
        "CL.TE": SmugglingVariant.CL_TE,
        "TE.CL": SmugglingVariant.TE_CL,
        "TE.TE": SmugglingVariant.TE_TE,
        "CL.CL": SmugglingVariant.CL_CL,
        "CL.0": SmugglingVariant.CL_0,
        "0.CL": SmugglingVariant.ZERO_CL,
        "H2.CL": SmugglingVariant.H2_CL,
        "H2.TE": SmugglingVariant.H2_TE,
        "H2.CRLF": SmugglingVariant.H2_CRLF,
        "H2.0": SmugglingVariant.H2_0,
        "h2c": SmugglingVariant.H2C,
        "WS.Version": SmugglingVariant.WS_VERSION,
        "WS.Upgrade": SmugglingVariant.WS_UPGRADE,
        "Pause": SmugglingVariant.PAUSE_BASED,
        "CSD": SmugglingVariant.CLIENT_SIDE,
    }
    
    result = set()
    for v in variants_str.split(","):
        v = v.strip()
        if v in variant_map:
            result.add(variant_map[v])
        else:
            console.print(f"[yellow]Warning: Unknown variant '{v}'[/yellow]")
    
    return result or {SmugglingVariant.CL_TE, SmugglingVariant.TE_CL}


def _parse_headers(header_tuples: tuple) -> dict:
    """Parse header tuples into dict."""
    headers = {}
    for h in header_tuples:
        if ":" in h:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def _parse_cookies(cookie_str: Optional[str]) -> dict:
    """Parse cookie string into dict."""
    if not cookie_str:
        return {}
    
    cookies = {}
    for pair in cookie_str.split(";"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


@cli.command()
@click.argument("target")
@click.option("--timeout", type=float, default=10.0)
def detect(target: str, timeout: float):
    """Detect protocols supported by TARGET.
    
    Performs protocol detection without active smuggling testing.
    If no scheme (http:// or https://) is provided, defaults to https://.
    """
    print_banner()
    
    from http_smuggler.detection.protocol import ProtocolDetector
    from http_smuggler.core.config import NetworkConfig
    from http_smuggler.utils.helpers import parse_url
    
    # Auto-add https:// if no scheme provided
    original_target = target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
        console.print(f"[dim]Note: No scheme provided, using https://[/dim]")
    
    # Parse and validate URL
    parsed = parse_url(target)
    if not parsed.host:
        console.print(f"[red]Error:[/red] Invalid URL: {original_target}")
        sys.exit(1)
    
    config = NetworkConfig(connect_timeout=timeout, read_timeout=timeout)
    detector = ProtocolDetector(config)
    
    async def run():
        result = await detector.detect(target)
        return result
    
    console.print(f"\n[cyan]Detecting protocols for:[/cyan] {target}\n")
    
    try:
        result = asyncio.run(run())
        
        table = Table(title="Protocol Detection Results", box=box.ROUNDED)
        table.add_column("Protocol/Feature", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Details", style="dim")
        
        # HTTP/1.1
        table.add_row(
            "HTTP/1.1",
            "[green]✓ Supported[/green]" if result.supports_http1 else "[red]✗ No[/red]",
            ""
        )
        
        # HTTP/2
        h2_details = ""
        if result.supports_http2:
            h2_details = f"via {result.h2_detection_method or 'unknown'}"
            if result.h2_verified:
                h2_details += " (verified)"
        table.add_row(
            "HTTP/2",
            "[green]✓ Supported[/green]" if result.supports_http2 else "[yellow]✗ Not detected[/yellow]",
            h2_details
        )
        
        # h2c
        table.add_row(
            "h2c (HTTP/2 Cleartext)",
            "[green]✓ Supported[/green]" if result.supports_h2c else "[dim]✗ No[/dim]",
            ""
        )
        
        # ALPN
        alpn_status = "[green]✓ Supported[/green]" if result.alpn_supported else "[yellow]✗ Not supported[/yellow]"
        alpn_details = ", ".join(result.alpn_protocols) if result.alpn_protocols else ""
        table.add_row("ALPN", alpn_status, alpn_details)
        
        # NPN (if detected)
        if result.npn_supported or result.npn_protocols:
            npn_details = ", ".join(result.npn_protocols) if result.npn_protocols else ""
            table.add_row("NPN (legacy)", "[green]✓ Supported[/green]", npn_details)
        
        # TLS version
        if result.tls_version:
            table.add_row("TLS Version", result.tls_version, "")
        
        # WebSocket
        ws_details = ", ".join(result.websocket_paths) if result.websocket_paths else ""
        table.add_row(
            "WebSocket",
            "[green]✓ Supported[/green]" if result.supports_websocket else "[dim]✗ No[/dim]",
            ws_details[:50] + "..." if len(ws_details) > 50 else ws_details
        )
        
        # Connection behavior
        table.add_row(
            "Keep-Alive",
            "[green]✓ Yes[/green]" if result.supports_keepalive else "[dim]✗ No[/dim]",
            ""
        )
        table.add_row(
            "Pipelining",
            "[green]✓ Yes[/green]" if result.supports_pipelining else "[dim]✗ No[/dim]",
            ""
        )
        
        console.print(table)
        
        # Server information
        if result.server_header or result.via_header or result.is_proxied:
            console.print()
            server_table = Table(title="Server Information", box=box.ROUNDED)
            server_table.add_column("Header", style="cyan")
            server_table.add_column("Value", style="white")
            
            if result.server_header:
                server_table.add_row("Server", result.server_header)
            
            if result.via_header:
                server_table.add_row("Via", result.via_header)
            
            if result.x_powered_by:
                server_table.add_row("X-Powered-By", result.x_powered_by)
            
            if result.is_proxied:
                server_table.add_row("Proxy Detected", result.proxy_type or "Unknown type")
            
            console.print(server_table)
        
        # Summary
        console.print()
        if result.supports_http2:
            console.print("[green]✓[/green] Target supports HTTP/2 - H2.CL, H2.TE, H2.CRLF attacks are applicable")
        if result.supports_h2c:
            console.print("[green]✓[/green] Target supports h2c upgrade - h2c tunneling attacks are applicable")
        if result.supports_websocket:
            console.print("[green]✓[/green] Target supports WebSocket - WS.Version, WS.Upgrade attacks are applicable")
        if result.is_proxied:
            console.print("[yellow]![/yellow] Proxy/CDN detected - Classic CL.TE, TE.CL, TE.TE attacks are most relevant")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@cli.command()
def list_variants():
    """List all supported smuggling variants."""
    print_banner()
    
    table = Table(title="Supported Smuggling Variants", box=box.ROUNDED)
    table.add_column("Variant", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Category", style="yellow")
    
    variants = [
        ("CL.TE", "Content-Length vs Transfer-Encoding", "Classic"),
        ("TE.CL", "Transfer-Encoding vs Content-Length", "Classic"),
        ("TE.TE", "Transfer-Encoding obfuscation", "Classic"),
        ("CL.CL", "Duplicate Content-Length", "Classic"),
        ("CL.0", "Content-Length ignored by backend", "Classic"),
        ("0.CL", "Frontend ignores Content-Length", "Classic"),
        ("H2.CL", "HTTP/2 Content-Length injection", "HTTP/2"),
        ("H2.TE", "HTTP/2 Transfer-Encoding injection", "HTTP/2"),
        ("H2.CRLF", "HTTP/2 CRLF injection", "HTTP/2"),
        ("H2.0", "HTTP/2 request tunneling", "HTTP/2"),
        ("h2c", "HTTP/2 Cleartext upgrade", "HTTP/2"),
        ("WS.Version", "WebSocket version smuggling", "WebSocket"),
        ("WS.Upgrade", "WebSocket upgrade abuse", "WebSocket"),
        ("Pause", "Pause-based desync", "Advanced"),
        ("CSD", "Client-Side Desync", "Advanced"),
    ]
    
    for variant, desc, category in variants:
        table.add_row(variant, desc, category)
    
    console.print(table)


@cli.command()
def list_obfuscations():
    """List all Transfer-Encoding obfuscations."""
    print_banner()
    
    from http_smuggler.payloads.obfuscation import TE_OBFUSCATIONS, get_categories_summary
    
    summary = get_categories_summary()
    
    console.print(f"\n[cyan]Total obfuscations:[/cyan] {len(TE_OBFUSCATIONS)}\n")
    
    table = Table(title="Obfuscation Categories", box=box.ROUNDED)
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="white")
    
    for cat, count in summary.items():
        table.add_row(cat.value, str(count))
    
    console.print(table)
    
    console.print("\n[dim]Use --verbose with scan to see individual obfuscations tested[/dim]")


# Import ReportConfig for the config
from http_smuggler.core.config import ReportConfig


if __name__ == "__main__":
    cli()

