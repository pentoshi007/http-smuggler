"""Structured logging utilities for HTTP Smuggler.

Uses structlog for structured logging with Rich for beautiful console output.
"""

import sys
import logging
from typing import Optional, Any, Dict
from datetime import datetime
from enum import Enum

import structlog
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme
from rich.style import Style


class LogLevel(Enum):
    """Log levels for the application."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# Custom theme for HTTP Smuggler
SMUGGLER_THEME = Theme({
    "info": Style(color="cyan"),
    "warning": Style(color="yellow", bold=True),
    "error": Style(color="red", bold=True),
    "critical": Style(color="red", bold=True, underline=True),
    "success": Style(color="green", bold=True),
    "vulnerability": Style(color="red", bold=True),
    "safe": Style(color="green"),
    "payload": Style(color="magenta"),
    "timing": Style(color="blue"),
    "endpoint": Style(color="cyan", italic=True),
})

# Global console instance
console = Console(theme=SMUGGLER_THEME)


def add_timestamp(
    logger: logging.Logger,
    method_name: str,
    event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add ISO timestamp to log events."""
    event_dict["timestamp"] = datetime.utcnow().isoformat() + "Z"
    return event_dict


def add_log_level(
    logger: logging.Logger,
    method_name: str,
    event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add log level to event dict."""
    event_dict["level"] = method_name.upper()
    return event_dict


def setup_logging(
    level: str = "INFO",
    json_output: bool = False,
    log_file: Optional[str] = None,
    quiet: bool = False,
) -> structlog.BoundLogger:
    """Configure structured logging for the application.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_output: If True, output JSON format instead of pretty console
        log_file: Optional file path to write logs to
        quiet: If True, suppress console output
    
    Returns:
        Configured structlog logger
    """
    # Set up standard library logging
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    handlers = []
    
    if not quiet:
        # Rich handler for console output
        rich_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
            tracebacks_show_locals=True,
            markup=True,
        )
        rich_handler.setLevel(log_level)
        handlers.append(rich_handler)
    
    if log_file:
        # File handler for log file output
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True,
    )
    
    # Configure structlog processors
    processors = [
        structlog.stdlib.filter_by_level,
        add_timestamp,
        add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]
    
    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(
            colors=True,
            exception_formatter=structlog.dev.plain_traceback,
        ))
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    return structlog.get_logger("http_smuggler")


def get_logger(name: str = "http_smuggler") -> structlog.BoundLogger:
    """Get a logger instance with the given name.
    
    Args:
        name: Logger name (usually module name)
    
    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


class ScanLogger:
    """Specialized logger for scan operations with Rich output."""
    
    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self.logger = get_logger("scan")
        self._stats = {
            "endpoints_tested": 0,
            "vulnerabilities_found": 0,
            "errors": 0,
        }
    
    def scan_start(self, target: str) -> None:
        """Log scan start."""
        if not self.quiet:
            console.print(f"\n[bold cyan]Starting scan of[/bold cyan] [endpoint]{target}[/endpoint]")
            console.print("─" * 60)
    
    def scan_complete(self, duration: float) -> None:
        """Log scan completion."""
        if not self.quiet:
            console.print("─" * 60)
            console.print(
                f"[bold green]Scan complete[/bold green] in {duration:.2f}s | "
                f"Endpoints: {self._stats['endpoints_tested']} | "
                f"Vulnerabilities: [vulnerability]{self._stats['vulnerabilities_found']}[/vulnerability]"
            )
    
    def protocol_detected(self, protocol: str, details: Dict[str, Any]) -> None:
        """Log protocol detection results."""
        if not self.quiet:
            console.print(f"[info]Protocol:[/info] {protocol}")
            if self.verbose:
                for key, value in details.items():
                    console.print(f"  {key}: {value}")
    
    def endpoint_testing(self, endpoint: str) -> None:
        """Log endpoint being tested."""
        self._stats["endpoints_tested"] += 1
        if self.verbose and not self.quiet:
            console.print(f"[info]Testing:[/info] [endpoint]{endpoint}[/endpoint]")
    
    def payload_sent(self, payload_name: str, variant: str) -> None:
        """Log payload being sent."""
        if self.verbose and not self.quiet:
            console.print(f"  [payload]Payload:[/payload] {payload_name} ({variant})")
    
    def vulnerability_found(
        self,
        variant: str,
        endpoint: str,
        confidence: float,
        severity: str,
    ) -> None:
        """Log vulnerability discovery."""
        self._stats["vulnerabilities_found"] += 1
        if not self.quiet:
            severity_color = {
                "CRITICAL": "red bold",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan",
            }.get(severity, "white")
            
            console.print(
                f"\n[vulnerability]🔓 VULNERABILITY FOUND[/vulnerability]\n"
                f"  Variant: [bold]{variant}[/bold]\n"
                f"  Endpoint: [endpoint]{endpoint}[/endpoint]\n"
                f"  Confidence: {confidence:.0%}\n"
                f"  Severity: [{severity_color}]{severity}[/{severity_color}]"
            )
    
    def timing_result(
        self,
        endpoint: str,
        baseline: float,
        actual: float,
        is_timeout: bool,
    ) -> None:
        """Log timing detection result."""
        if self.verbose and not self.quiet:
            status = "[timing]TIMEOUT[/timing]" if is_timeout else "[safe]OK[/safe]"
            console.print(
                f"  [timing]Timing:[/timing] baseline={baseline:.2f}s, "
                f"actual={actual:.2f}s {status}"
            )
    
    def error(self, message: str, exception: Optional[Exception] = None) -> None:
        """Log error."""
        self._stats["errors"] += 1
        if not self.quiet:
            console.print(f"[error]Error:[/error] {message}")
            if exception and self.verbose:
                console.print_exception()
    
    def warning(self, message: str) -> None:
        """Log warning."""
        if not self.quiet:
            console.print(f"[warning]Warning:[/warning] {message}")
    
    def info(self, message: str) -> None:
        """Log info message."""
        if not self.quiet:
            console.print(f"[info]Info:[/info] {message}")
    
    def debug(self, message: str) -> None:
        """Log debug message."""
        if self.verbose and not self.quiet:
            console.print(f"[dim]Debug:[/dim] {message}")
    
    def waf_detected(self, waf_name: Optional[str] = None) -> None:
        """Log WAF detection."""
        if not self.quiet:
            name = waf_name or "Unknown"
            console.print(f"[warning]⚠ WAF Detected:[/warning] {name}")
    
    def rate_limited(self, retry_after: Optional[float] = None) -> None:
        """Log rate limiting."""
        if not self.quiet:
            msg = f"[warning]Rate limited[/warning]"
            if retry_after:
                msg += f" - waiting {retry_after:.1f}s"
            console.print(msg)
    
    @property
    def stats(self) -> Dict[str, int]:
        """Get current statistics."""
        return self._stats.copy()


# Default logger instance
_default_logger: Optional[structlog.BoundLogger] = None


def init_default_logger(
    level: str = "INFO",
    json_output: bool = False,
    log_file: Optional[str] = None,
    quiet: bool = False,
) -> structlog.BoundLogger:
    """Initialize and return the default logger."""
    global _default_logger
    _default_logger = setup_logging(level, json_output, log_file, quiet)
    return _default_logger


def log() -> structlog.BoundLogger:
    """Get the default logger, initializing if necessary."""
    global _default_logger
    if _default_logger is None:
        _default_logger = setup_logging()
    return _default_logger

