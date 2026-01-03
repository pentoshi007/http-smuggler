#!/bin/bash
#
# HTTP-Smuggler Start Script (Linux/macOS)
# Automatically sets up the environment if needed, then starts the tool
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print banner
print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  _   _ _____ _____ ____    ____                              _           
 | | | |_   _|_   _|  _ \  / ___| _ __ ___  _   _  __ _  __ _| | ___ _ __ 
 | |_| | | |   | | | |_) | \___ \| '_ ` _ \| | | |/ _` |/ _` | |/ _ \ '__|
 |  _  | | |   | | |  __/   ___) | | | | | | |_| | (_| | (_| | |  __/ |   
 |_| |_| |_|   |_| |_|     |____/|_| |_| |_|\__,_|\__, |\__, |_|\___|_|   
                                                  |___/ |___/             
EOF
    echo -e "${NC}"
    echo -e "${GREEN}HTTP Request Smuggling Detection & Exploitation Tool${NC}"
    echo ""
}

# Check if setup is needed
needs_setup() {
    # Check if venv exists and http-smuggler is installed
    if [ -d "venv" ] && [ -f "venv/bin/http-smuggler" ]; then
        return 1  # No setup needed
    fi
    return 0  # Setup needed
}

# Find suitable Python (3.9+)
find_python() {
    # List of Python commands to try, in order of preference (newer first)
    for cmd in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
        if command -v "$cmd" &> /dev/null; then
            version=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
            if [ -n "$version" ]; then
                major=$(echo "$version" | cut -d. -f1)
                minor=$(echo "$version" | cut -d. -f2)
                # Ensure major and minor are valid integers
                if [[ "$major" =~ ^[0-9]+$ ]] && [[ "$minor" =~ ^[0-9]+$ ]]; then
                    if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
                        echo "$cmd"
                        return 0
                    fi
                fi
            fi
        fi
    done
    return 1
}

# Run setup
run_setup() {
    echo -e "${YELLOW}══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  First-time setup detected. Installing dependencies...${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════${NC}"
    echo ""

    # Check Python version
    echo -e "${BLUE}[1/4] Checking Python version...${NC}"
    
    PYTHON_CMD=$(find_python)
    
    if [ -n "$PYTHON_CMD" ]; then
        PYTHON_VERSION=$("$PYTHON_CMD" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        echo -e "${GREEN}       ✓ Found $PYTHON_CMD ($PYTHON_VERSION)${NC}"
    else
        # Show what's available and how to install
        echo -e "${RED}       ✗ Python 3.9+ required${NC}"
        echo ""
        
        # Check what Python versions are installed
        echo -e "${YELLOW}Installed Python versions:${NC}"
        for cmd in python python3 python3.8 python3.9 python3.10 python3.11 python3.12 python3.13; do
            if command -v "$cmd" &> /dev/null; then
                ver=$("$cmd" --version 2>&1 | head -1)
                echo -e "  - $cmd: $ver"
            fi
        done
        echo ""
        
        # Provide installation instructions based on OS
        echo -e "${CYAN}To install Python 3.11+ on your system:${NC}"
        echo ""
        if [ -f /etc/debian_version ]; then
            echo -e "${GREEN}Ubuntu/Debian:${NC}"
            echo "  sudo apt update"
            echo "  sudo apt install python3.11 python3.11-venv python3.11-dev"
            echo ""
            echo -e "${YELLOW}Or use deadsnakes PPA for newer versions:${NC}"
            echo "  sudo add-apt-repository ppa:deadsnakes/ppa"
            echo "  sudo apt update"
            echo "  sudo apt install python3.11 python3.11-venv"
        elif [ -f /etc/redhat-release ]; then
            echo -e "${GREEN}RHEL/CentOS/Fedora:${NC}"
            echo "  sudo dnf install python3.11"
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            echo -e "${GREEN}macOS (using Homebrew):${NC}"
            echo "  brew install python@3.11"
        else
            echo -e "${GREEN}Generic (using pyenv):${NC}"
            echo "  curl https://pyenv.run | bash"
            echo "  pyenv install 3.11"
            echo "  pyenv global 3.11"
        fi
        echo ""
        echo -e "${YELLOW}After installing, run ./start.sh again${NC}"
        exit 1
    fi

    # Create virtual environment
    echo -e "${BLUE}[2/4] Creating virtual environment...${NC}"
    "$PYTHON_CMD" -m venv venv
    echo -e "${GREEN}       ✓ Created${NC}"

    # Activate and install
    echo -e "${BLUE}[3/4] Installing dependencies...${NC}"
    source venv/bin/activate
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
    echo -e "${GREEN}       ✓ Dependencies installed${NC}"

    # Install package
    echo -e "${BLUE}[4/4] Installing http-smuggler...${NC}"
    pip install -e . -q
    echo -e "${GREEN}       ✓ Installed${NC}"

    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Setup complete!${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Activate environment
activate_env() {
    source venv/bin/activate
}

# Show help
show_help() {
    echo -e "${CYAN}Usage:${NC}"
    echo -e "  ./start.sh                    # Show interactive menu"
    echo -e "  ./start.sh detect <URL>       # Detect protocols"
    echo -e "  ./start.sh detect <URL> -v    # Detect protocols (verbose)"
    echo -e "  ./start.sh scan <URL>         # Full vulnerability scan"
    echo -e "  ./start.sh scan <URL> -v      # Full scan (verbose output)"
    echo -e "  ./start.sh <any command>      # Pass directly to http-smuggler"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo -e "  ./start.sh detect https://example.com"
    echo -e "  ./start.sh detect https://example.com -v"
    echo -e "  ./start.sh scan https://target.com -o report.json"
    echo -e "  ./start.sh scan https://target.com --mode aggressive"
    echo -e "  ./start.sh scan https://target.com -v"
    echo -e "  ./start.sh list-variants"
    echo ""
}

# Interactive menu
show_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}What would you like to do?${NC}"
        echo ""
        echo -e "  ${GREEN}1)${NC} Detect protocols on a target"
        echo -e "  ${GREEN}2)${NC} Scan for vulnerabilities"
        echo -e "  ${GREEN}3)${NC} List supported variants"
        echo -e "  ${GREEN}4)${NC} List TE obfuscations"
        echo -e "  ${GREEN}5)${NC} Show help"
        echo -e "  ${GREEN}6)${NC} Open shell with environment"
        echo -e "  ${GREEN}q)${NC} Quit"
        echo ""
        read -p "Select option: " choice

        case $choice in
            1)
                echo ""
                read -p "Enter target URL: " target_url
                if [ -n "$target_url" ]; then
                    read -p "Verbose output? (y/N): " verbose
                    echo ""
                    if [ "$verbose" = "y" ] || [ "$verbose" = "Y" ]; then
                        http-smuggler detect "$target_url" -v
                    else
                        http-smuggler detect "$target_url"
                    fi
                fi
                echo ""
                echo -e "${YELLOW}Press Enter to continue...${NC}"
                read
                ;;
            2)
                echo ""
                read -p "Enter target URL: " target_url
                if [ -n "$target_url" ]; then
                    read -p "Output file (leave empty for console): " output_file
                    read -p "Verbose output? (y/N): " verbose
                    echo ""
                    cmd_args="$target_url"
                    if [ -n "$output_file" ]; then
                        cmd_args="$cmd_args -o \"$output_file\""
                    fi
                    if [ "$verbose" = "y" ] || [ "$verbose" = "Y" ]; then
                        cmd_args="$cmd_args -v"
                    fi
                    eval "http-smuggler scan $cmd_args"
                fi
                echo ""
                echo -e "${YELLOW}Press Enter to continue...${NC}"
                read
                ;;
            3)
                echo ""
                http-smuggler list-variants
                echo ""
                echo -e "${YELLOW}Press Enter to continue...${NC}"
                read
                ;;
            4)
                echo ""
                http-smuggler list-obfuscations
                echo ""
                echo -e "${YELLOW}Press Enter to continue...${NC}"
                read
                ;;
            5)
                echo ""
                http-smuggler --help
                echo ""
                echo -e "${YELLOW}Press Enter to continue...${NC}"
                read
                ;;
            6)
                echo -e "${GREEN}Environment activated. Type 'exit' to return to menu.${NC}"
                echo -e "${BLUE}Try: http-smuggler --help${NC}"
                $SHELL
                ;;
            q|Q)
                echo ""
                echo -e "${GREEN}Goodbye! 👋${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac
    done
}

# Main
print_banner

# Check and run setup if needed
if needs_setup; then
    run_setup
fi

# Activate environment
activate_env

# If arguments provided, pass them to http-smuggler
if [ $# -gt 0 ]; then
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        show_help
        http-smuggler --help
    else
        http-smuggler "$@"
    fi
else
    # No arguments - show interactive menu
    show_menu
fi

