#!/bin/bash
#
# HTTP-Smuggler Setup Script (Linux/macOS)
# This script sets up the environment and installs dependencies
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
cat << 'EOF'
  _   _ _____ _____ ____    ____                              _           
 | | | |_   _|_   _|  _ \  / ___| _ __ ___  _   _  __ _  __ _| | ___ _ __ 
 | |_| | | |   | | | |_) | \___ \| '_ ` _ \| | | |/ _` |/ _` | |/ _ \ '__|
 |  _  | | |   | | |  __/   ___) | | | | | | |_| | (_| | (_| | |  __/ |   
 |_| |_| |_|   |_| |_|     |____/|_| |_| |_|\__,_|\__, |\__, |_|\___|_|   
                                                  |___/ |___/             
EOF
echo -e "${NC}"
echo -e "${GREEN}HTTP Request Smuggling Detection Tool - Setup${NC}"
echo ""

# Check Python version
echo -e "${YELLOW}[1/5] Checking Python version...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 9 ]; then
        echo -e "${GREEN}  ✓ Python $PYTHON_VERSION detected${NC}"
    else
        echo -e "${RED}  ✗ Python 3.9+ required, found $PYTHON_VERSION${NC}"
        exit 1
    fi
else
    echo -e "${RED}  ✗ Python 3 not found. Please install Python 3.9+${NC}"
    exit 1
fi

# Create virtual environment
echo -e "${YELLOW}[2/5] Creating virtual environment...${NC}"
if [ -d "venv" ]; then
    echo -e "${BLUE}  → Virtual environment already exists${NC}"
else
    python3 -m venv venv
    echo -e "${GREEN}  ✓ Virtual environment created${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}[3/5] Activating virtual environment...${NC}"
source venv/bin/activate
echo -e "${GREEN}  ✓ Virtual environment activated${NC}"

# Upgrade pip
echo -e "${YELLOW}[4/5] Installing dependencies...${NC}"
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "${GREEN}  ✓ Dependencies installed${NC}"

# Install package in development mode
echo -e "${YELLOW}[5/5] Installing http-smuggler...${NC}"
pip install -e . -q
echo -e "${GREEN}  ✓ http-smuggler installed${NC}"

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "To activate the environment in the future, run:"
echo -e "${BLUE}  source venv/bin/activate${NC}"
echo ""
echo -e "Quick start commands:"
echo -e "${BLUE}  http-smuggler --help${NC}              # Show help"
echo -e "${BLUE}  http-smuggler detect <URL>${NC}        # Detect protocols"
echo -e "${BLUE}  http-smuggler scan <URL>${NC}          # Full vulnerability scan"
echo -e "${BLUE}  http-smuggler list-variants${NC}       # List smuggling variants"
echo ""
echo -e "Example:"
echo -e "${BLUE}  http-smuggler detect https://example.com${NC}"
echo ""

# Verify installation
echo -e "${YELLOW}Verifying installation...${NC}"
if http-smuggler --version &> /dev/null; then
    VERSION=$(http-smuggler --version)
    echo -e "${GREEN}  ✓ $VERSION${NC}"
else
    echo -e "${RED}  ✗ Installation verification failed${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Ready to use! 🚀${NC}"

