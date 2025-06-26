#!/bin/bash

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Progress indicator function
show_progress() {
    local message="$1"
    echo -e "${CYAN}[INFO]${NC} ${message}..."
}

# Success indicator function
show_success() {
    local message="$1"
    echo -e "${GREEN}[✓]${NC} ${message}"
}

# Error indicator function
show_error() {
    local message="$1"
    echo -e "${RED}[✗]${NC} ${message}" >&2
}

# Warning indicator function
show_warning() {
    local message="$1"
    echo -e "${YELLOW}[!]${NC} ${message}"
}

# Banner function
show_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║               ${BOLD}Aviatrix Legacy Policy Exporter Installer${NC}${BLUE}                ║"
    echo "║                                                                              ║"
    echo "║                    Quick setup for AWS/Azure CloudShell                     ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
}

# Main installation function
main() {
    show_banner
    
    # Check if we're in a supported environment
    show_progress "Checking environment"
    if [[ -n "$AZURE_HTTP_USER_AGENT" ]]; then
        ENV_TYPE="Azure CloudShell"
    elif [[ -n "$AWS_EXECUTION_ENV" ]] || [[ "$HOME" == "/home/cloudshell-user" ]]; then
        ENV_TYPE="AWS CloudShell"
    else
        ENV_TYPE="Generic Linux"
        show_warning "Not detected as AWS or Azure CloudShell, but continuing anyway"
    fi
    show_success "Environment detected: $ENV_TYPE"
    
    # Check Python version
    show_progress "Checking Python version"
    if ! command -v python3 &> /dev/null; then
        show_error "Python 3 is not installed"
        exit 1
    fi
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    show_success "Python $PYTHON_VERSION found"
    
    # Check pip
    show_progress "Checking pip installation"
    if ! command -v pip3 &> /dev/null; then
        show_error "pip3 is not installed"
        exit 1
    fi
    show_success "pip3 is available"
    
    # Create working directory
    show_progress "Creating working directory"
    WORK_DIR="$HOME/aviatrix-policy-exporter"
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"
    show_success "Working directory created: $WORK_DIR"
    
    # Create virtual environment
    show_progress "Creating Python virtual environment"
    if python3 -m venv venv; then
        show_success "Virtual environment created"
    else
        show_error "Failed to create virtual environment"
        exit 1
    fi
    
    # Activate virtual environment
    show_progress "Activating virtual environment"
    source venv/bin/activate
    show_success "Virtual environment activated"
    
    # Download requirements.txt
    show_progress "Downloading requirements.txt"
    if curl -fsSL "https://raw.githubusercontent.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator/refs/heads/main/exporter/requirements.txt" -o requirements.txt; then
        show_success "requirements.txt downloaded"
    else
        show_error "Failed to download requirements.txt"
        exit 1
    fi
    
    # Install Python dependencies
    show_progress "Installing Python dependencies in virtual environment"
    if pip install -r requirements.txt; then
        show_success "Python dependencies installed"
    else
        show_error "Failed to install Python dependencies"
        exit 1
    fi
    
    # Download export script
    show_progress "Downloading export_legacy_policy_bundle.py"
    if curl -fsSL "https://raw.githubusercontent.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator/refs/heads/main/exporter/export_legacy_policy_bundle.py" -o export_legacy_policy_bundle.py; then
        show_success "export_legacy_policy_bundle.py downloaded"
    else
        show_error "Failed to download export_legacy_policy_bundle.py"
        exit 1
    fi
    
    # Make script executable
    chmod +x export_legacy_policy_bundle.py
    show_success "Script made executable"
    
    # Installation complete
    echo
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║                            INSTALLATION COMPLETE!                           ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    # Usage instructions
    echo -e "${BOLD}${BLUE}HOW TO USE:${NC}"
    echo
    echo -e "${YELLOW}1. Navigate to the installation directory:${NC}"
    echo -e "   ${CYAN}cd $WORK_DIR${NC}"
    echo
    echo -e "${YELLOW}2. Activate the virtual environment:${NC}"
    echo -e "   ${CYAN}source venv/bin/activate${NC}"
    echo
    echo -e "${YELLOW}3. Run the exporter script:${NC}"
    echo -e "   ${CYAN}python export_legacy_policy_bundle.py -i <controller_ip> -u <username>${NC}"
    echo
    echo -e "${YELLOW}4. Available options:${NC}"
    echo -e "   ${CYAN}-i, --controller-ip${NC}    Controller IP address (required)"
    echo -e "   ${CYAN}-u, --username${NC}         Username (required)"
    echo -e "   ${CYAN}-p, --password${NC}         Password (optional, will prompt if not provided)"
    echo -e "   ${CYAN}-o, --output${NC}           Output file (default: policy_bundle_YYYYMMDD_HHMMSS.json)"
    echo -e "   ${CYAN}-w, --write-password${NC}   Write password to output file (use with caution)"
    echo
    echo -e "${YELLOW}5. Example usage:${NC}"
    echo -e "   ${CYAN}python export_legacy_policy_bundle.py -i 10.0.0.100 -u admin${NC}"
    echo -e "   ${CYAN}python export_legacy_policy_bundle.py -i controller.example.com -u admin -o my_policies.json${NC}"
    echo
    echo -e "${YELLOW}6. When finished, deactivate the virtual environment:${NC}"
    echo -e "   ${CYAN}deactivate${NC}"
    echo
    echo -e "${BOLD}${GREEN}Files are ready in: $WORK_DIR${NC}"
    echo -e "${BOLD}${GREEN}You can now export your Aviatrix legacy policies!${NC}"
    echo
}

# Error handling
trap 'show_error "Installation failed at line $LINENO. Check the error above."' ERR

# Run main function
main "$@"