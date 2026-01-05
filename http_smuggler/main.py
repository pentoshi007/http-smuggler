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
@click.version_option(version="1.1.0", prog_name="http-smuggler")
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
    "--auto-listeners/--no-auto-listeners",
    default=True,
    help="Auto-start callback listeners for exploitation (capture server, fake101, loot)"
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
    auto_listeners: bool,
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

    SMART MODE: In aggressive mode with --exploit, the tool automatically starts
    the appropriate callback listeners based on vulnerability type:

    \b
    - CL.TE/TE.CL/TE.TE → Capture server for session hijacking (port 8888)
    - WS.VERSION → Fake 101 server for WebSocket SSRF (port 9999)
    - CLIENT_SIDE → Loot server for cookie exfiltration (port 8080)

    No manual intervention required - the tool has the brain to do it!

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

    # Show smart mode info
    if not quiet and mode == "aggressive" and (exploit or config.exploit.enabled) and auto_listeners:
        from http_smuggler.network.callback_server import get_local_ip
        local_ip = get_local_ip()
        console.print("\n[bold cyan]SMART MODE ENABLED[/bold cyan]")
        console.print("[dim]Auto-listeners will start automatically when vulnerabilities are found:[/dim]")
        console.print(f"  [green]•[/green] Capture server: http://{local_ip}:8888/")
        console.print(f"  [green]•[/green] Fake 101 server: http://{local_ip}:9999/")
        console.print(f"  [green]•[/green] Loot server: http://{local_ip}:8080/")
        console.print()

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
        task = progress.add_task("[cyan]Initializing...", total=100)

        # Create a task that monitors progress and updates the progress bar
        async def update_progress():
            last_phase = ""
            while True:
                p = engine.progress
                # Calculate overall progress based on current phase
                if p.phase == "protocol_detection":
                    progress.update(task, completed=5, description="[cyan]Detecting protocols...")
                elif p.phase == "crawling":
                    progress.update(task, completed=15, description="[cyan]Crawling endpoints...")
                elif p.phase == "testing":
                    if p.total_endpoints > 0:
                        # Scale testing phase from 20-95%
                        endpoint_progress = (p.tested_endpoints / p.total_endpoints) * 75
                        completed = 20 + endpoint_progress
                        progress.update(
                            task,
                            completed=completed,
                            description=f"[cyan]Testing endpoints ({p.tested_endpoints}/{p.total_endpoints})..."
                        )
                elif p.phase == "complete":
                    progress.update(task, completed=100, description="[cyan]Scan complete")
                    break

                if last_phase != p.phase:
                    last_phase = p.phase

                await asyncio.sleep(0.1)

        # Run scan and progress updater concurrently
        scan_task = asyncio.create_task(engine.scan())
        progress_task = asyncio.create_task(update_progress())

        try:
            result = await scan_task
        finally:
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass

        progress.update(task, completed=100, description="[cyan]Scan complete")

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
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def detect(target: str, timeout: float, verbose: bool):
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
    
    # Setup logging based on verbose flag
    log_level = "DEBUG" if verbose else "INFO"
    setup_logging(level=log_level, quiet=False)

    config = NetworkConfig(connect_timeout=timeout, read_timeout=timeout)
    detector = ProtocolDetector(config)

    async def run():
        result = await detector.detect(target)
        return result

    console.print(f"\n[cyan]Detecting protocols for:[/cyan] {target}\n")

    if verbose:
        console.print(f"[dim]Timeout: {timeout}s[/dim]")
    
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


@cli.command()
@click.option(
    "--type", "-t",
    type=click.Choice(["capture", "fake101", "loot"]),
    default="capture",
    help="Listener type: capture (request capture), fake101 (WebSocket SSRF), loot (cookie/token capture)"
)
@click.option(
    "--port", "-p",
    type=int,
    default=8888,
    help="Port to listen on"
)
@click.option(
    "--host", "-H",
    default="0.0.0.0",
    help="Host to bind to"
)
@click.option(
    "--timeout",
    type=float,
    default=300.0,
    help="Server timeout in seconds (default: 5 minutes)"
)
def listener(type: str, port: int, host: str, timeout: float):
    """Start a callback listener for exploitation.

    Useful for TryHackMe labs and real-world testing where you need
    an external server to receive callbacks.

    Examples:

        # Start capture server for session hijacking
        http-smuggler listener --type capture --port 8888

        # Start Fake 101 server for WebSocket SSRF (Method B)
        http-smuggler listener --type fake101 --port 9999

        # Start loot server for Client-Side Desync attacks
        http-smuggler listener --type loot --port 8080
    """
    print_banner()

    from http_smuggler.network.callback_server import (
        CallbackServer,
        CallbackServerConfig,
        get_local_ip,
    )

    local_ip = get_local_ip()

    config = CallbackServerConfig(
        host=host,
        port=port,
        timeout=timeout,
    )

    server = CallbackServer(config)

    console.print(f"\n[cyan]Starting {type} listener...[/cyan]\n")

    if type == "capture":
        console.print("[bold]Request Capture Server[/bold]")
        console.print("Captures incoming HTTP requests for session hijacking attacks.\n")

        def on_capture(req):
            console.print(f"[green]✓ Captured:[/green] {req.method} {req.path} from {req.source_ip}")
            console.print(f"  Headers: {dict(list(req.headers.items())[:3])}...")
            if req.body:
                console.print(f"  Body: {req.body[:100]}...")

        if not server.start_capture_server(on_capture=on_capture):
            console.print("[red]Failed to start server![/red]")
            sys.exit(1)

    elif type == "fake101":
        console.print("[bold]Fake 101 Server (WebSocket SSRF)[/bold]")
        console.print("Returns 101 Switching Protocols for WebSocket SSRF attacks.\n")
        console.print("[dim]Use this when the target has an SSRF endpoint that you can")
        console.print("point to your server to establish a fake WebSocket tunnel.[/dim]\n")

        if not server.start_fake101_server():
            console.print("[red]Failed to start server![/red]")
            sys.exit(1)

    elif type == "loot":
        console.print("[bold]Loot Collection Server[/bold]")
        console.print("Captures exfiltrated cookies and tokens from CSD attacks.\n")

        if not server.start_loot_server():
            console.print("[red]Failed to start server![/red]")
            sys.exit(1)

    console.print(f"[green]✓ Listening on {host}:{port}[/green]")
    console.print(f"[cyan]External URL:[/cyan] http://{local_ip}:{port}/")
    console.print("\n[dim]Press Ctrl+C to stop[/dim]\n")

    try:
        import time
        start = time.time()
        while time.time() - start < timeout:
            time.sleep(1)

            # Show captured requests for capture type
            if type == "capture":
                captures = server.get_captures()
                if captures:
                    console.print(f"[dim]Total captured: {len(captures)}[/dim]", end="\r")

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping listener...[/yellow]")
    finally:
        server.stop()

    # Print summary
    if type == "capture":
        captures = server.get_captures()
        if captures:
            console.print(f"\n[green]Captured {len(captures)} request(s):[/green]")
            for i, cap in enumerate(captures[:10]):
                console.print(f"  {i+1}. {cap.method} {cap.path} from {cap.source_ip}")
        else:
            console.print("\n[yellow]No requests captured[/yellow]")

    elif type == "loot":
        loot = server.get_loot()
        if loot:
            console.print(f"\n[green]Captured {len(loot)} loot item(s):[/green]")
            for i, item in enumerate(loot[:10]):
                console.print(f"  {i+1}. {item.get('path', 'unknown')}")
                if "cookie" in str(item.get("params", {})).lower():
                    console.print(f"     [red]COOKIE FOUND![/red]")


# Import ReportConfig for the config
from http_smuggler.core.config import ReportConfig


if __name__ == "__main__":
    cli()

