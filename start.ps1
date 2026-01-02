#
# HTTP-Smuggler Start Script (Windows PowerShell)
# Automatically sets up the environment if needed, then starts the tool
#

param(
    [Parameter(Position=0, ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"

# Print banner
function Show-Banner {
    Write-Host @"

  _   _ _____ _____ ____    ____                              _           
 | | | |_   _|_   _|  _ \  / ___| _ __ ___  _   _  __ _  __ _| | ___ _ __ 
 | |_| | | |   | | | |_) | \___ \| '_ ` _ \| | | |/ _` |/ _` | |/ _ \ '__|
 |  _  | | |   | | |  __/   ___) | | | | | | |_| | (_| | (_| | |  __/ |   
 |_| |_| |_|   |_| |_|     |____/|_| |_| |_|\__,_|\__, |\__, |_|\___|_|   
                                                  |___/ |___/             

"@ -ForegroundColor Cyan
    Write-Host "HTTP Request Smuggling Detection & Exploitation Tool" -ForegroundColor Green
    Write-Host ""
}

# Check if setup is needed
function Test-NeedsSetup {
    if ((Test-Path "venv") -and (Test-Path "venv\Scripts\http-smuggler.exe")) {
        return $false
    }
    return $true
}

# Run setup
function Invoke-Setup {
    Write-Host "===========================================================" -ForegroundColor Yellow
    Write-Host "  First-time setup detected. Installing dependencies..." -ForegroundColor Yellow
    Write-Host "===========================================================" -ForegroundColor Yellow
    Write-Host ""

    # Check Python version
    Write-Host "[1/4] Checking Python version..." -ForegroundColor Blue
    try {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "Python (\d+)\.(\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 9) {
                Write-Host "      [OK] $pythonVersion" -ForegroundColor Green
            } else {
                Write-Host "      [ERROR] Python 3.9+ required, found $pythonVersion" -ForegroundColor Red
                exit 1
            }
        }
    } catch {
        Write-Host "      [ERROR] Python not found. Install from https://python.org" -ForegroundColor Red
        exit 1
    }

    # Create virtual environment
    Write-Host "[2/4] Creating virtual environment..." -ForegroundColor Blue
    python -m venv venv
    Write-Host "      [OK] Created" -ForegroundColor Green

    # Activate and install
    Write-Host "[3/4] Installing dependencies..." -ForegroundColor Blue
    & .\venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip -q 2>$null
    pip install -r requirements.txt -q 2>$null
    Write-Host "      [OK] Dependencies installed" -ForegroundColor Green

    # Install package
    Write-Host "[4/4] Installing http-smuggler..." -ForegroundColor Blue
    pip install -e . -q 2>$null
    Write-Host "      [OK] Installed" -ForegroundColor Green

    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host "  Setup complete!" -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host ""
}

# Activate environment
function Enable-Environment {
    & .\venv\Scripts\Activate.ps1
}

# Show help
function Show-Help {
    Write-Host "Usage:" -ForegroundColor Cyan
    Write-Host "  .\start.ps1                    # Show interactive menu"
    Write-Host "  .\start.ps1 detect <URL>       # Detect protocols"
    Write-Host "  .\start.ps1 scan <URL>         # Full vulnerability scan"
    Write-Host "  .\start.ps1 <any command>      # Pass directly to http-smuggler"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Cyan
    Write-Host "  .\start.ps1 detect https://example.com"
    Write-Host "  .\start.ps1 scan https://target.com -o report.json"
    Write-Host "  .\start.ps1 scan https://target.com --mode aggressive"
    Write-Host "  .\start.ps1 list-variants"
    Write-Host ""
}

# Interactive menu
function Show-Menu {
    Write-Host "What would you like to do?" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1) Detect protocols on a target" -ForegroundColor White
    Write-Host "  2) Scan for vulnerabilities" -ForegroundColor White
    Write-Host "  3) List supported variants" -ForegroundColor White
    Write-Host "  4) List TE obfuscations" -ForegroundColor White
    Write-Host "  5) Show help" -ForegroundColor White
    Write-Host "  6) Open shell with environment" -ForegroundColor White
    Write-Host "  q) Quit" -ForegroundColor White
    Write-Host ""
    
    $choice = Read-Host "Select option"

    switch ($choice) {
        "1" {
            $targetUrl = Read-Host "Enter target URL"
            if ($targetUrl) {
                http-smuggler detect $targetUrl
            }
        }
        "2" {
            $targetUrl = Read-Host "Enter target URL"
            if ($targetUrl) {
                $outputFile = Read-Host "Output file (leave empty for console)"
                if ($outputFile) {
                    http-smuggler scan $targetUrl -o $outputFile
                } else {
                    http-smuggler scan $targetUrl
                }
            }
        }
        "3" {
            http-smuggler list-variants
        }
        "4" {
            http-smuggler list-obfuscations
        }
        "5" {
            http-smuggler --help
        }
        "6" {
            Write-Host "Environment activated. Type 'exit' to leave." -ForegroundColor Green
            Write-Host "Try: http-smuggler --help" -ForegroundColor Blue
            cmd /k
        }
        "q" {
            Write-Host "Goodbye!" -ForegroundColor Green
            exit 0
        }
        default {
            Write-Host "Invalid option" -ForegroundColor Red
        }
    }
}

# Main
Show-Banner

# Check and run setup if needed
if (Test-NeedsSetup) {
    Invoke-Setup
}

# Activate environment
Enable-Environment

# If arguments provided, pass them to http-smuggler
if ($Arguments.Count -gt 0) {
    if ($Arguments[0] -eq "--help" -or $Arguments[0] -eq "-h") {
        Show-Help
        http-smuggler --help
    } else {
        & http-smuggler @Arguments
    }
} else {
    # No arguments - show interactive menu
    Show-Menu
}

