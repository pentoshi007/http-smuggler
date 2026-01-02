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

# Run setup
run_setup() {
    echo -e "${YELLOW}══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  First-time setup detected. Installing dependencies...${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════${NC}"
    echo ""

    # Check Python version
    echo -e "${BLUE}[1/4] Checking Python version...${NC}"
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 9 ]; then
            echo -e "${GREEN}       ✓ Python $PYTHON_VERSION${NC}"
        else
            echo -e "${RED}       ✗ Python 3.9+ required, found $PYTHON_VERSION${NC}"
            exit 1
        fi
    else
        echo -e "${RED}       ✗ Python 3 not found. Please install Python 3.9+${NC}"
        exit 1
    fi

    # Create virtual environment
    echo -e "${BLUE}[2/4] Creating virtual environment...${NC}"
    python3 -m venv venv
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
    echo -e "  ./start.sh scan <URL>         # Full vulnerability scan"
    echo -e "  ./start.sh <any command>      # Pass directly to http-smuggler"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo -e "  ./start.sh detect https://example.com"
    echo -e "  ./start.sh scan https://target.com -o report.json"
    echo -e "  ./start.sh scan https://target.com --mode aggressive"
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
                    echo ""
                    http-smuggler detect "$target_url"
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
                    echo ""
                    if [ -n "$output_file" ]; then
                        http-smuggler scan "$target_url" -o "$output_file"
                    else
                        http-smuggler scan "$target_url"
                    fi
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

