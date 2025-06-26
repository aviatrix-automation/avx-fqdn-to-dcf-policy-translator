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
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                                              ║${NC}"
    echo -e "${BLUE}║                ${BOLD}Aviatrix Legacy Policy Exporter Installer${NC}${BLUE}               ║${NC}"
    echo -e "${BLUE}║                                                                              ║${NC}"
    echo -e "${BLUE}║                     Quick setup for AWS/Azure CloudShell                    ║${NC}"
    echo -e "${BLUE}║                                                                              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
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
        show_warning "Not detected as AWS or Azure CloudShell, continuing anyway"
    fi
    show_success "Environment detected: $ENV_TYPE"
    
    # Get CloudShell public IP for later display
    show_progress "Detecting CloudShell public IP address"
    CLOUDSHELL_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || curl -s icanhazip.com 2>/dev/null)
    if [[ -n "$CLOUDSHELL_IP" ]]; then
        show_success "CloudShell public IP detected: $CLOUDSHELL_IP"
    else
        show_warning "Could not detect CloudShell public IP automatically"
    fi
    
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
    echo -e "${BOLD}${BLUE}QUICK START:${NC}"
    echo
    echo -e "${YELLOW}Copy and paste these 3 lines to start the script:${NC}"
    echo
    echo -e "   ${CYAN}cd $WORK_DIR${NC}"
    echo -e "   ${CYAN}source venv/bin/activate${NC}"
    echo -e "   ${CYAN}python export_legacy_policy_bundle.py${NC}"
    echo
    echo -e "${YELLOW}The script will run in interactive mode and guide you through setup.${NC}"
    echo
    echo -e "${BOLD}${BLUE}ADVANCED OPTIONS:${NC}"
    echo
    echo -e "${YELLOW}For command-line options and non-interactive usage, run:${NC}"
    echo -e "   ${CYAN}python export_legacy_policy_bundle.py --help${NC}"
    echo
    echo -e "${YELLOW}When finished, deactivate the virtual environment:${NC}"
    echo -e "   ${CYAN}deactivate${NC}"
    echo
    echo -e "${BOLD}${GREEN}Files are ready in: $WORK_DIR${NC}"
    echo -e "${BOLD}${GREEN}You can now export your Aviatrix legacy policies!${NC}"
    echo
    
    # Display security group configuration warning
    if [[ -n "$CLOUDSHELL_IP" ]]; then
        echo -e "${RED}${BOLD}⚠️  IMPORTANT SECURITY GROUP CONFIGURATION ⚠️${NC}"
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}║  Before running the export script, you MUST update your Aviatrix            ║${NC}"
        echo -e "${YELLOW}║  Controller's security group to allow access from this CloudShell IP:       ║${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}║  ${BOLD}CloudShell IP: ${CLOUDSHELL_IP}${NC}${YELLOW}                                               ║${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}║  Add this IP to your controller's security group for:                       ║${NC}"
        echo -e "${YELLOW}║  • Port 443 (HTTPS) - for controller API access                             ║${NC}"
        echo -e "${YELLOW}║  • Port 443 (HTTPS) - for CoPilot access (if using CoPilot)                ║${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}║  ${BOLD}Steps:${NC}${YELLOW}                                                                   ║${NC}"
        echo -e "${YELLOW}║  1. Go to your cloud provider's console (AWS/Azure/GCP)                     ║${NC}"
        echo -e "${YELLOW}║  2. Find the security group attached to your Aviatrix Controller            ║${NC}"
        echo -e "${YELLOW}║  3. Add an inbound rule: HTTPS (443) from ${CLOUDSHELL_IP}/32               ║${NC}"
        echo -e "${YELLOW}║  4. If using CoPilot, repeat for CoPilot's security group                   ║${NC}"
        echo -e "${YELLOW}║  5. Save the changes                                                         ║${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}║  ${BOLD}Remember to remove this IP from the security group when finished!${NC}${YELLOW}       ║${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "${RED}${BOLD}🔒 SECURITY REMINDER:${NC}"
        echo -e "${YELLOW}Don't forget to remove ${CLOUDSHELL_IP}/32 from your controller's${NC}"
        echo -e "${YELLOW}security group when you're finished with the export!${NC}"
        echo
    else
        echo -e "${RED}${BOLD}⚠️  IMPORTANT SECURITY GROUP CONFIGURATION ⚠️${NC}"
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}║  Before running the export script, you MUST update your Aviatrix            ║${NC}"
        echo -e "${YELLOW}║  Controller's security group to allow access from this CloudShell IP.       ║${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}║  To find your CloudShell IP, run: curl ifconfig.me                          ║${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}║  Then add that IP to your controller's security group for:                  ║${NC}"
        echo -e "${YELLOW}║  • Port 443 (HTTPS) - for controller API access                             ║${NC}"
        echo -e "${YELLOW}║  • Port 443 (HTTPS) - for CoPilot access (if using CoPilot)                ║${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}║  ${BOLD}Remember to remove this IP from the security group when finished!${NC}${YELLOW}       ║${NC}"
        echo -e "${YELLOW}║                                                                              ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo
    fi
}

# Error handling
trap 'show_error "Installation failed at line $LINENO. Check the error above."' ERR

# Run main function
main "$@"