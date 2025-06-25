#!/bin/bash
#
# cloudshell_exporter.sh
#
# Aviatrix Legacy Policy Exporter for CloudShell Environments
# 
# This script provides a user-friendly interface for exporting legacy
# Aviatrix firewall and FQDN policies from both Controller and CoPilot.
# Optimized for AWS CloudShell and Azure CloudShell environments.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator/refs/heads/main/exporter/cloudshell_exporter.sh | bash
#
# Requirements:
#   - AWS CloudShell or Azure CloudShell
#   - Network access to your Aviatrix Controller
#   - Valid Aviatrix Controller credentials
#
# Output:
#   - legacy_policy_bundle.zip containing exported policies
#
# Author: Aviatrix Systems
# Project: https://github.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator
#

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
BASE_URL="https://raw.githubusercontent.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator/refs/heads/main/exporter"
EXPORTER_URL="${BASE_URL}/export_legacy_policy_bundle.py"
REQUIREMENTS_URL="${BASE_URL}/requirements.txt"

# Colors for visual appeal (with fallback for non-color terminals)
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput colors >/dev/null 2>&1 && [[ $(tput colors) -ge 8 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

# Global variables
TEMP_DIR=""
CONTROLLER_IP=""
USERNAME=""
PASSWORD=""

# Cleanup function
cleanup() {
    if [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]]; then
        echo -e "\n${YELLOW}🧹 Cleaning up temporary files...${NC}"
        rm -rf "$TEMP_DIR"
        echo -e "${GREEN}✅ Cleanup completed${NC}"
    fi
    
    # Clear sensitive variables
    unset PASSWORD
    unset USERNAME
    unset CONTROLLER_IP
}

# Trap EXIT to ensure cleanup
trap cleanup EXIT

# Display banner
display_banner() {
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}☁️  Aviatrix CloudShell Policy Exporter${NC}               ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}  ${BLUE}═══════════════════════════════════════════════════${NC}   ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}                                                         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}  Export legacy firewall and FQDN policies from your    ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}  Aviatrix Controller and CoPilot for migration to      ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}  Distributed Cloud Firewall (DCF).                     ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}                                                         ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}  ${BLUE}🔗 github.com/aviatrix-automation/...${NC}                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}  ${GREEN}☁️  Optimized for AWS and Azure CloudShell${NC}            ${CYAN}│${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# Check requirements
check_requirements() {
    echo -e "${BLUE}🔍 Checking environment requirements...${NC}"
    
    # Check for required tools
    local missing_tools=()
    
    if ! command -v python3 >/dev/null 2>&1; then
        missing_tools+=("python3")
    fi
    
    if ! command -v pip3 >/dev/null 2>&1; then
        missing_tools+=("pip3")
    fi
    
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        missing_tools+=("curl or wget")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}❌ Error: Missing required tools: ${missing_tools[*]}${NC}"
        echo -e "${YELLOW}💡 This script is designed for AWS CloudShell or Azure CloudShell${NC}"
        exit 1
    fi
    
    # Check network connectivity
    echo -e "   ${CYAN}🌐 Testing network connectivity...${NC}"
    if command -v curl >/dev/null 2>&1; then
        if ! curl -sSf --connect-timeout 10 https://github.com >/dev/null 2>&1; then
            echo -e "${RED}❌ Error: Cannot reach GitHub. Check your internet connection.${NC}"
            exit 1
        fi
    else
        if ! wget -q --timeout=10 --spider https://github.com >/dev/null 2>&1; then
            echo -e "${RED}❌ Error: Cannot reach GitHub. Check your internet connection.${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}✅ Environment check passed${NC}"
}

# Validate IP address format
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    else
        # Allow hostnames/FQDNs
        if [[ $ip =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            return 0
        fi
        return 1
    fi
}

# Collect user inputs
collect_inputs() {
    echo -e "${BOLD}📋 Please provide your Aviatrix Controller details:${NC}"
    echo ""
    
    # Controller IP
    while true; do
        echo -ne "${CYAN}🌐 Controller IP Address or FQDN: ${NC}"
        read -r CONTROLLER_IP
        
        if [[ -z "$CONTROLLER_IP" ]]; then
            echo -e "${RED}❌ Controller IP cannot be empty${NC}"
            continue
        fi
        
        if validate_ip "$CONTROLLER_IP"; then
            break
        else
            echo -e "${RED}❌ Please enter a valid IP address or hostname${NC}"
        fi
    done
    
    # Username
    while true; do
        echo -ne "${CYAN}👤 Username: ${NC}"
        read -r USERNAME
        
        if [[ -z "$USERNAME" ]]; then
            echo -e "${RED}❌ Username cannot be empty${NC}"
            continue
        fi
        break
    done
    
    # Password (hidden input)
    while true; do
        echo -ne "${CYAN}🔒 Password: ${NC}"
        read -rs PASSWORD
        echo ""
        
        if [[ -z "$PASSWORD" ]]; then
            echo -e "${RED}❌ Password cannot be empty${NC}"
            continue
        fi
        break
    done
    
    echo ""
}

# Confirm execution
confirm_execution() {
    echo -e "${CYAN}┌─────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${BOLD}✅ Configuration Summary${NC}                ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${BLUE}──────────────────────────────────────${NC} ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} Controller: ${GREEN}${CONTROLLER_IP}${NC}"
    
    # Pad the controller IP line to align properly
    local padding_length=$((37 - ${#CONTROLLER_IP}))
    printf "${CYAN}│${NC}%*s${CYAN}│${NC}\n" "$padding_length" ""
    
    echo -e "${CYAN}│${NC} Username:   ${GREEN}${USERNAME}${NC}"
    
    # Pad the username line
    padding_length=$((37 - ${#USERNAME}))
    printf "${CYAN}│${NC}%*s${CYAN}│${NC}\n" "$padding_length" ""
    
    echo -e "${CYAN}│${NC} Password:   ${GREEN}••••••••••••${NC}               ${CYAN}│${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────┘${NC}"
    echo ""
    
    echo -ne "${BOLD}🚀 Proceed with export? [Y/n]: ${NC}"
    read -r confirm
    if [[ $confirm =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}⛔ Export cancelled by user${NC}"
        exit 0
    fi
    echo ""
}

# Setup environment
setup_environment() {
    echo -e "${BLUE}🔧 Setting up CloudShell environment...${NC}"
    TEMP_DIR=$(mktemp -d -t avx-cloudshell-XXXXXX)
    cd "$TEMP_DIR"
    echo -e "${GREEN}📁 Working directory: ${TEMP_DIR}${NC}"
}

# Download files with progress indication
download_files() {
    echo -e "${BLUE}⬇️  Downloading exporter tools...${NC}"
    
    download_with_progress() {
        local url=$1
        local filename=$2
        echo -ne "   ${CYAN}📥 ${filename}...${NC} "
        
        if command -v curl >/dev/null 2>&1; then
            if curl -sSL --fail --connect-timeout 30 "$url" -o "$filename"; then
                echo -e "${GREEN}✅${NC}"
                return 0
            else
                echo -e "${RED}❌${NC}"
                return 1
            fi
        else
            if wget -q --timeout=30 "$url" -O "$filename"; then
                echo -e "${GREEN}✅${NC}"
                return 0
            else
                echo -e "${RED}❌${NC}"
                return 1
            fi
        fi
    }
    
    # Download main exporter script
    if ! download_with_progress "$EXPORTER_URL" "export_legacy_policy_bundle.py"; then
        echo -e "${RED}❌ Error: Failed to download exporter script${NC}"
        exit 1
    fi
    
    # Download requirements
    if ! download_with_progress "$REQUIREMENTS_URL" "requirements.txt"; then
        echo -e "${RED}❌ Error: Failed to download requirements file${NC}"
        exit 1
    fi
    
    # Verify downloads
    if [[ ! -f "export_legacy_policy_bundle.py" ]] || [[ ! -f "requirements.txt" ]]; then
        echo -e "${RED}❌ Error: Downloaded files not found${NC}"
        exit 1
    fi
    
    # Basic integrity check
    if [[ $(wc -c < export_legacy_policy_bundle.py) -lt 1000 ]]; then
        echo -e "${RED}❌ Error: Downloaded exporter script appears corrupted${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ All files downloaded successfully${NC}"
}

# Install Python dependencies
install_dependencies() {
    echo -e "${BLUE}📦 Installing Python dependencies...${NC}"
    
    # Install with user flag to avoid permission issues
    if python3 -m pip install -r requirements.txt --quiet --user --disable-pip-version-check; then
        echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
    else
        echo -e "${RED}❌ Error: Failed to install dependencies${NC}"
        echo -e "${YELLOW}💡 Try running: python3 -m pip install --upgrade pip${NC}"
        exit 1
    fi
}

# Run the exporter
run_exporter() {
    echo -e "${BLUE}🚀 Running Aviatrix Policy Exporter...${NC}"
    echo -e "${CYAN}🔌 Connecting to Controller: ${CONTROLLER_IP}${NC}"
    
    # Execute the exporter with all output visible
    if python3 export_legacy_policy_bundle.py \
        -i "$CONTROLLER_IP" \
        -u "$USERNAME" \
        -p "$PASSWORD" \
        -o legacy_policy_bundle.zip; then
        echo -e "\n${GREEN}✅ Export completed successfully!${NC}"
    else
        echo -e "\n${RED}❌ Export failed. Please check:${NC}"
        echo -e "${YELLOW}   • Controller IP address and connectivity${NC}"
        echo -e "${YELLOW}   • Username and password${NC}"
        echo -e "${YELLOW}   • Network connectivity to Controller and CoPilot${NC}"
        exit 1
    fi
}

# Display results
display_results() {
    if [[ -f "legacy_policy_bundle.zip" ]]; then
        local size=$(du -h legacy_policy_bundle.zip 2>/dev/null | cut -f1 || echo "unknown")
        echo ""
        echo -e "${GREEN}🎉 Success! Policy bundle created:${NC}"
        echo -e "${CYAN}┌─────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│${NC} ${BOLD}📦 File:${NC} legacy_policy_bundle.zip       ${CYAN}│${NC}"
        echo -e "${CYAN}│${NC} ${BOLD}📏 Size:${NC} ${size}                          ${CYAN}│${NC}"
        echo -e "${CYAN}│${NC} ${BOLD}📁 Path:${NC} $(pwd)    ${CYAN}│${NC}"
        echo -e "${CYAN}└─────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "${BOLD}📋 Next Steps:${NC}"
        echo -e "${YELLOW}   1. Download the bundle to your local machine${NC}"
        echo -e "${YELLOW}   2. Use the translator tool to convert policies to DCF format${NC}"
        echo -e "${YELLOW}   3. Deploy with Terraform${NC}"
        echo ""
        echo -e "${BLUE}📖 For translator usage instructions:${NC}"
        echo -e "${CYAN}   https://github.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator${NC}"
        echo ""
    else
        echo -e "${RED}❌ Error: Output file not found${NC}"
        exit 1
    fi
}

# Cleanup prompt
cleanup_prompt() {
    echo -ne "${BOLD}🧹 Clean up temporary files? [Y/n]: ${NC}"
    read -r cleanup_confirm
    if [[ ! $cleanup_confirm =~ ^[Nn]$ ]]; then
        # Copy the bundle to a persistent location first
        if [[ -f "legacy_policy_bundle.zip" ]]; then
            cp legacy_policy_bundle.zip "$HOME/"
            echo -e "${GREEN}📋 Bundle copied to: ${HOME}/legacy_policy_bundle.zip${NC}"
        fi
        echo -e "${YELLOW}🧹 Temporary files will be cleaned up automatically${NC}"
    else
        echo -e "${YELLOW}⚠️  Temporary files preserved in: ${TEMP_DIR}${NC}"
        echo -e "${YELLOW}   Remember to clean up manually when done${NC}"
        # Disable automatic cleanup
        trap - EXIT
    fi
}

# Main execution function
main() {
    display_banner
    check_requirements
    collect_inputs
    confirm_execution
    setup_environment
    download_files
    install_dependencies
    run_exporter
    display_results
    cleanup_prompt
}

# Execute main function
main "$@"