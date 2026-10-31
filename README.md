# HTTP-Smuggler

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/payloads-100+-orange.svg" alt="100+ Payloads">
</p>

**HTTP Request Smuggling Detection & Exploitation Tool**

A protocol-aware scanner for detecting and validating request smuggling vulnerabilities across HTTP/1.1, HTTP/2, and WebSocket surfaces with an explicit capability matrix.

## ✨ Features

- 🔍 **Protocol Detection** - ALPN negotiation, HTTP/2, h2c, and WebSocket detection
- 🕷️ **Domain Crawling** - Automatically discovers endpoints via sitemaps and recursive crawling
- 🎯 **Payload Matrix** - Variant-specific timing and differential payloads
- ⚡ **Async Architecture** - Fast concurrent testing with rate limiting
- 🛡️ **Safety Modes** - Passive, Safe, Normal, and Aggressive scan modes
- 🎭 **Exploitation** - Optional confirmation with actual exploitation attempts
- 📊 **Multi-Format Reports** - JSON, Markdown, and Text output
- 🧠 **Smart Mode** - Auto-starts the right callback listeners based on vulnerability type
- 🎧 **Built-in Listeners** - Capture server, Fake 101 server, and Loot server for exploitation

## 🚀 Variant Capability Matrix

Run `http-smuggler list-variants` to view the live matrix from the internal registry.

### Classic HTTP/1.1

| Variant   | Description                                                  | Status |
| --------- | ------------------------------------------------------------ | ------ |
| **CL.TE** | Frontend uses Content-Length, Backend uses Transfer-Encoding | Implemented |
| **TE.CL** | Frontend uses Transfer-Encoding, Backend uses Content-Length | Implemented |
| **TE.TE** | Transfer-Encoding obfuscation                                 | Implemented |
| **CL.CL** | Duplicate Content-Length headers                             | Planned |
| **CL.0**  | Backend ignores Content-Length                               | Planned |
| **0.CL**  | Frontend ignores body, Backend reads CL                      | Planned |

### HTTP/2

| Variant     | Description                                         | Status |
| ----------- | --------------------------------------------------- | ------ |
| **H2.CL**   | HTTP/2 to HTTP/1.1 with Content-Length injection    | Implemented |
| **H2.TE**   | HTTP/2 to HTTP/1.1 with Transfer-Encoding injection | Implemented |
| **H2.CRLF** | CRLF injection in HTTP/2 headers                    | Implemented |
| **H2.0**    | HTTP/2 request tunneling                            | Planned |
| **h2c**     | Cleartext HTTP/2 upgrade smuggling                  | Planned |

### WebSocket

| Variant        | Description                        | Status |
| -------------- | ---------------------------------- | ------ |
| **WS.Version** | Sec-WebSocket-Version manipulation | Implemented |
| **WS.Upgrade** | Upgrade header smuggling           | Planned |

### Advanced

| Variant         | Description                               | Status |
| --------------- | ----------------------------------------- | ------ |
| **Pause-Based** | Timeout exploitation via strategic pauses | Experimental |
| **Client-Side** | Browser-powered desync (CSD)              | Experimental |

## 📦 Installation

### Quick Start (Recommended)

```bash
# Clone the repository
git clone https://github.com/pentoshi007/http-smuggler.git
cd http-smuggler

# Linux/macOS:
./start.sh

# Windows (PowerShell):
.\start.ps1
```

The start script automatically:

- Sets up virtual environment on first run
- Installs all dependencies
- Shows interactive menu or runs commands directly

```bash
# Run commands directly
./start.sh detect https://example.com
./start.sh scan https://target.com -o report.json
# For verbose output
./start.sh detect https://example.com -v
./start.sh scan https://target.com -v -o report.json

```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/pentoshi007/http-smuggler.git
cd http-smuggler

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or: .\venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## 🔧 Quick Start

```bash
# Basic scan
http-smuggler scan https://target.com

# Save report as JSON
http-smuggler scan https://target.com -o report.json

# Aggressive mode with exploitation (SMART MODE - auto-starts listeners)
http-smuggler scan https://target.com --mode aggressive --exploit

# Protocol detection only
http-smuggler detect https://target.com

# Test specific variants only
http-smuggler scan https://target.com --variants CL.TE,TE.CL,H2.CL

# Skip crawling, test single endpoint
http-smuggler scan https://target.com/api --no-crawl

# Disable auto-listeners (manual listener mode)
http-smuggler scan https://target.com --mode aggressive --exploit --no-auto-listeners
```

## 📖 Usage

```
Usage: http-smuggler [OPTIONS] COMMAND [ARGS]...

Commands:
  scan              Scan target for HTTP request smuggling vulnerabilities
  detect            Protocol detection only (no smuggling tests)
  listener          Start a callback listener for exploitation
  list-variants     List smuggling variant capability matrix
  list-obfuscations List all Transfer-Encoding obfuscations

Global Options:
  --version  Show version
  --help     Show help message
```

### Scan Options

```
http-smuggler scan [OPTIONS] TARGET

Options:
  -m, --mode [passive|safe|normal|aggressive]
                              Scan mode (default: normal)
  --profile [labs|safe]       Environment profile (default: labs)
  --confidence-mode [high|balanced|recall]
                              Detection strictness (default: high)
  --confirm-attempts INTEGER  Confirmation attempts per payload (default: 2)
  -o, --output PATH           Output file path
  -f, --format [json|markdown|text]
                              Output format (default: json)
  --crawl / --no-crawl        Enable/disable crawling (default: enabled)
  --exploit / --no-exploit    Enable exploitation (default: disabled)
  --auto-listeners / --no-auto-listeners
                              Auto-start callback listeners (default: enabled)
  --depth INTEGER             Maximum crawl depth (default: 3)
  --max-endpoints INTEGER     Maximum endpoints to test (default: 100)
  --variants TEXT             Comma-separated variants to test
  --http2-only                Test only HTTP/2 variants
  --classic-only              Test only classic HTTP/1.1 variants
  -H, --header TEXT           Custom header (can be repeated)
  -c, --cookie TEXT           Cookies to include
  --timeout FLOAT             Request timeout in seconds (default: 10)
  --rate-limit FLOAT          Requests per second (default: 2)
  -v, --verbose               Verbose output
  -q, --quiet                 Quiet mode
```

### Scan Modes

| Mode           | Description                             | Use Case           |
| -------------- | --------------------------------------- | ------------------ |
| **passive**    | Protocol detection only                 | Reconnaissance     |
| **safe**       | Timing detection only (single requests) | Production systems |
| **normal**     | Timing + Differential detection         | Standard testing   |
| **aggressive** | Full testing with exploitation          | Lab environments   |

### Smart Mode (Auto-Listeners)

When running in aggressive mode with `--exploit`, the tool automatically starts the appropriate callback listeners based on vulnerability type:

| Vulnerability Type | Auto-Started Listener | Purpose |
| ------------------ | --------------------- | ------- |
| CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, H2.CRLF | Capture Server (port 8888) | Session hijacking |
| WS.VERSION | Fake 101 Server (port 9999) | WebSocket SSRF |
| Client-Side Desync | Loot Server (port 8080) | Cookie exfiltration |

**No manual intervention required** - the tool figures out what listener is needed and starts it automatically.

### Listener Command

For manual testing or advanced usage, you can start listeners independently:

```bash
# Start capture server for session hijacking
http-smuggler listener --type capture --port 8888

# Start Fake 101 server for WebSocket SSRF attacks
http-smuggler listener --type fake101 --port 9999

# Start loot server for Client-Side Desync attacks
http-smuggler listener --type loot --port 8080
```

Listener options:
```
http-smuggler listener [OPTIONS]

Options:
  -t, --type [capture|fake101|loot]  Listener type (default: capture)
  -p, --port INTEGER                  Port to listen on (default: 8888)
  -H, --host TEXT                     Host to bind to (default: 0.0.0.0)
  --timeout FLOAT                     Server timeout in seconds (default: 300)
```

## 📋 Example Output

### JSON Report

```json
{
  "target": "https://vulnerable-site.com",
  "scan_start": "2024-01-15T10:30:00Z",
  "scan_end": "2024-01-15T10:35:42Z",
  "protocol_profile": {
    "primary_version": "HTTP/1.1",
    "alpn_protocols": ["h2", "http/1.1"],
    "supports_http2": true,
    "supports_websocket": false
  },
  "endpoints_tested": 45,
  "vulnerabilities": [
    {
      "variant": "CL.TE",
      "endpoint": "/api/submit",
      "severity": "HIGH",
      "detection_result": {
        "method": "differential",
        "confidence": 0.95,
        "evidence": "GPOST method error in victim response"
      },
      "exploitation": {
        "successful": true,
        "impact": "Request poisoning confirmed"
      }
    }
  ]
}
```

### Console Output

```
  _   _ _____ _____ ____    ____                              _
 | | | |_   _|_   _|  _ \  / ___| _ __ ___  _   _  __ _  __ _| | ___ _ __
 | |_| | | |   | | | |_) | \___ \| '_ ` _ \| | | |/ _` |/ _` | |/ _ \ '__|
 |  _  | | |   | | |  __/   ___) | | | | | | |_| | (_| | (_| | |  __/ |
 |_| |_| |_|   |_| |_|     |____/|_| |_| |_|\__,_|\__, |\__, |_|\___|_|
                                                  |___/ |___/

Starting scan of https://vulnerable-site.com
────────────────────────────────────────────────────────────────
Info: Detecting supported protocols...
Protocol: HTTP/1.1
  alpn: ['h2', 'http/1.1']
  h2c: False
  websocket: False
Info: Found 45 endpoints to test

🔓 VULNERABILITY FOUND
  Variant: CL.TE
  Endpoint: /api/submit
  Confidence: 95%
  Severity: HIGH

────────────────────────────────────────────────────────────────
Scan complete in 342.15s | Endpoints: 45 | Vulnerabilities: 1
```

## 🏗️ Architecture

```
http_smuggler/
├── core/           # Configuration, models, exceptions, engine
├── network/        # Raw socket, HTTP/2 clients, callback servers
├── detection/      # Protocol, timing, differential detectors
├── payloads/       # Payload generators (classic, http2, websocket, advanced)
├── crawler/        # Async domain crawler
├── exploits/       # Exploitation runners, auto-listener management
├── analysis/       # Report generation
├── utils/          # Logging, helpers
└── main.py         # CLI interface
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation.

## 🎓 TryHackMe Compatibility

This tool is tested and compatible with TryHackMe HTTP Smuggling labs:

| Room | Variants Covered | Notes |
| ---- | ---------------- | ----- |
| HTTP Request Smuggling | CL.TE, TE.CL | Classic smuggling basics |
| HTTP/2 Request Smuggling | H2.CL, H2.TE, H2.CRLF | HTTP/2 downgrade attacks |
| WebSocket Request Smuggling | WS.VERSION | Version manipulation + SSRF |
| Client-Side Desync | CSD | Browser-powered attacks |

For TryHackMe labs, use aggressive mode:
```bash
http-smuggler scan http://TARGET_IP --mode aggressive --exploit
```

The tool will automatically start the appropriate listeners for capturing sessions or performing SSRF.

## 🧪 Testing

```bash
# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=http_smuggler --cov-report=html
```

## ⚠️ Legal Notice

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is intended for security professionals conducting authorized penetration testing and vulnerability assessments. Unauthorized access to computer systems is illegal.

- ✅ Always obtain explicit written permission before testing
- ✅ Only test systems you own or have authorization to test
- ❌ Never use against production systems without approval
- ❌ Do not use for malicious purposes

The authors are not responsible for misuse of this tool.

## 📚 References

- [HTTP Desync Attacks - PortSwigger Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
