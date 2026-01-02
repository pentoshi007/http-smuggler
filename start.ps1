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

# Find suitable Python (3.9+)
function Find-Python {
    # List of Python commands to try, in order of preference (newer first)
    $pythonCommands = @("python3.13", "python3.12", "python3.11", "python3.10", "python3.9", "python3", "python", "py -3.13", "py -3.12", "py -3.11", "py -3.10", "py -3.9", "py")
    
    foreach ($cmd in $pythonCommands) {
        try {
            $cmdParts = $cmd -split " "
            if ($cmdParts.Count -gt 1) {
                $result = & $cmdParts[0] $cmdParts[1] --version 2>&1
            } else {
                $result = & $cmd --version 2>&1
            }
            
            if ($result -match "Python (\d+)\.(\d+)") {
                $major = [int]$Matches[1]
                $minor = [int]$Matches[2]
                if ($major -ge 3 -and $minor -ge 9) {
                    return @{
                        Command = $cmd
                        Version = "$major.$minor"
                    }
                }
            }
        } catch {
            # Command not found, try next
        }
    }
    return $null
}

# Run setup
function Invoke-Setup {
    Write-Host "===========================================================" -ForegroundColor Yellow
    Write-Host "  First-time setup detected. Installing dependencies..." -ForegroundColor Yellow
    Write-Host "===========================================================" -ForegroundColor Yellow
    Write-Host ""

    # Check Python version
    Write-Host "[1/4] Checking Python version..." -ForegroundColor Blue
    
    $pythonInfo = Find-Python
    
    if ($pythonInfo) {
        Write-Host "      [OK] Found $($pythonInfo.Command) ($($pythonInfo.Version))" -ForegroundColor Green
        $script:PythonCmd = $pythonInfo.Command
    } else {
        Write-Host "      [ERROR] Python 3.9+ required" -ForegroundColor Red
        Write-Host ""
        
        # Check what Python versions are installed
        Write-Host "Installed Python versions:" -ForegroundColor Yellow
        foreach ($cmd in @("python", "python3", "py")) {
            try {
                $ver = & $cmd --version 2>&1
                Write-Host "  - $cmd : $ver"
            } catch {}
        }
        Write-Host ""
        
        # Provide installation instructions
        Write-Host "To install Python 3.11+ on Windows:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Option 1: Download from python.org" -ForegroundColor Green
        Write-Host "  Visit: https://www.python.org/downloads/"
        Write-Host "  Download Python 3.11 or newer"
        Write-Host "  During install, check 'Add Python to PATH'"
        Write-Host ""
        Write-Host "Option 2: Using winget" -ForegroundColor Green
        Write-Host "  winget install Python.Python.3.11"
        Write-Host ""
        Write-Host "Option 3: Using chocolatey" -ForegroundColor Green
        Write-Host "  choco install python311"
        Write-Host ""
        Write-Host "After installing, restart your terminal and run .\start.ps1 again" -ForegroundColor Yellow
        exit 1
    }

    # Create virtual environment
    Write-Host "[2/4] Creating virtual environment..." -ForegroundColor Blue
    $cmdParts = $script:PythonCmd -split " "
    if ($cmdParts.Count -gt 1) {
        & $cmdParts[0] $cmdParts[1] -m venv venv
    } else {
        & $script:PythonCmd -m venv venv
    }
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
    while ($true) {
        Write-Host ""
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
                Write-Host ""
                $targetUrl = Read-Host "Enter target URL"
                if ($targetUrl) {
                    Write-Host ""
                    http-smuggler detect $targetUrl
                }
                Write-Host ""
                Write-Host "Press Enter to continue..." -ForegroundColor Yellow
                Read-Host
            }
            "2" {
                Write-Host ""
                $targetUrl = Read-Host "Enter target URL"
                if ($targetUrl) {
                    $outputFile = Read-Host "Output file (leave empty for console)"
                    Write-Host ""
                    if ($outputFile) {
                        http-smuggler scan $targetUrl -o $outputFile
                    } else {
                        http-smuggler scan $targetUrl
                    }
                }
                Write-Host ""
                Write-Host "Press Enter to continue..." -ForegroundColor Yellow
                Read-Host
            }
            "3" {
                Write-Host ""
                http-smuggler list-variants
                Write-Host ""
                Write-Host "Press Enter to continue..." -ForegroundColor Yellow
                Read-Host
            }
            "4" {
                Write-Host ""
                http-smuggler list-obfuscations
                Write-Host ""
                Write-Host "Press Enter to continue..." -ForegroundColor Yellow
                Read-Host
            }
            "5" {
                Write-Host ""
                http-smuggler --help
                Write-Host ""
                Write-Host "Press Enter to continue..." -ForegroundColor Yellow
                Read-Host
            }
            "6" {
                Write-Host "Environment activated. Type 'exit' to return to menu." -ForegroundColor Green
                Write-Host "Try: http-smuggler --help" -ForegroundColor Blue
                powershell
            }
            "q" {
                Write-Host ""
                Write-Host "Goodbye! " -ForegroundColor Green
                exit 0
            }
            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
            }
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

