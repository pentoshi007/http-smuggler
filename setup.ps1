#
# HTTP-Smuggler Setup Script (Windows PowerShell)
# This script sets up the environment and installs dependencies
#

$ErrorActionPreference = "Stop"

# Colors
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

# Print banner
Write-Host @"

  _   _ _____ _____ ____    ____                              _           
 | | | |_   _|_   _|  _ \  / ___| _ __ ___  _   _  __ _  __ _| | ___ _ __ 
 | |_| | | |   | | | |_) | \___ \| '_ ` _ \| | | |/ _` |/ _` | |/ _ \ '__|
 |  _  | | |   | | |  __/   ___) | | | | | | |_| | (_| | (_| | |  __/ |   
 |_| |_| |_|   |_| |_|     |____/|_| |_| |_|\__,_|\__, |\__, |_|\___|_|   
                                                  |___/ |___/             

"@ -ForegroundColor Cyan

Write-Host "HTTP Request Smuggling Detection Tool - Setup" -ForegroundColor Green
Write-Host ""

# Check Python version
Write-Host "[1/5] Checking Python version..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python (\d+)\.(\d+)") {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -ge 3 -and $minor -ge 9) {
            Write-Host "  [OK] $pythonVersion detected" -ForegroundColor Green
        } else {
            Write-Host "  [ERROR] Python 3.9+ required, found $pythonVersion" -ForegroundColor Red
            exit 1
        }
    }
} catch {
    Write-Host "  [ERROR] Python not found. Please install Python 3.9+" -ForegroundColor Red
    Write-Host "  Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Create virtual environment
Write-Host "[2/5] Creating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv") {
    Write-Host "  [INFO] Virtual environment already exists" -ForegroundColor Blue
} else {
    python -m venv venv
    Write-Host "  [OK] Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host "[3/5] Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1
Write-Host "  [OK] Virtual environment activated" -ForegroundColor Green

# Upgrade pip and install dependencies
Write-Host "[4/5] Installing dependencies..." -ForegroundColor Yellow
python -m pip install --upgrade pip -q 2>$null
pip install -r requirements.txt -q 2>$null
Write-Host "  [OK] Dependencies installed" -ForegroundColor Green

# Install package in development mode
Write-Host "[5/5] Installing http-smuggler..." -ForegroundColor Yellow
pip install -e . -q 2>$null
Write-Host "  [OK] http-smuggler installed" -ForegroundColor Green

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "To activate the environment in the future, run:" -ForegroundColor White
Write-Host "  .\venv\Scripts\Activate.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "Quick start commands:" -ForegroundColor White
Write-Host "  http-smuggler --help              # Show help" -ForegroundColor Cyan
Write-Host "  http-smuggler detect <URL>        # Detect protocols" -ForegroundColor Cyan
Write-Host "  http-smuggler scan <URL>          # Full vulnerability scan" -ForegroundColor Cyan
Write-Host "  http-smuggler list-variants       # List smuggling variants" -ForegroundColor Cyan
Write-Host ""
Write-Host "Example:" -ForegroundColor White
Write-Host "  http-smuggler detect https://example.com" -ForegroundColor Cyan
Write-Host ""

# Verify installation
Write-Host "Verifying installation..." -ForegroundColor Yellow
try {
    $version = http-smuggler --version 2>&1
    Write-Host "  [OK] $version" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Installation verification failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Ready to use! " -ForegroundColor Green -NoNewline
Write-Host ([char]::ConvertFromUtf32(0x1F680))

