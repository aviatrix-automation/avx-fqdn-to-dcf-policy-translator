# Legacy Policy Bundle Exporter

This directory contains the exporter tool for collecting legacy Aviatrix firewall and FQDN policies from Aviatrix Controller and CoPilot.

## Files

- **`export_legacy_policy_bundle.py`**: Main export script with CoPilot integration
- **`copilot_auth_function_example.py`**: Reference implementation for CoPilot authentication
- **`requirements.txt`**: Python dependencies for the exporter
- **`cloudshell_install.sh`**: Automated installer for AWS/Azure CloudShell
- **`README.md`**: This documentation file

## Installation

### Quick Install for AWS/Azure CloudShell

For the fastest setup in AWS CloudShell or Azure CloudShell, use the automated installer:

```bash
curl -fsSL https://raw.githubusercontent.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator/refs/heads/main/exporter/cloudshell_install.sh | bash
```

This will:
- Create a working directory (`~/aviatrix-policy-exporter`)
- Set up a Python virtual environment
- Download and install all dependencies
- Download the export script
- Provide usage instructions

### Manual Installation

Install the required dependencies:

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Export (Controller Only)
```bash
python export_legacy_policy_bundle.py -i <controller_ip> -u <username>
```

### Export with CoPilot Integration
```bash
# Auto-discover CoPilot IP
python export_legacy_policy_bundle.py -i <controller_ip> -u <username>

# Specify CoPilot IP manually
python export_legacy_policy_bundle.py -i <controller_ip> -u <username> --copilot-ip <copilot_ip>

# Skip CoPilot integration
python export_legacy_policy_bundle.py -i <controller_ip> -u <username> --skip-copilot
```

### Additional Options
```bash
# Include VPC route tables and Any-Web webgroup
python export_legacy_policy_bundle.py -i <controller_ip> -u <username> -w -r

# Custom output file
python export_legacy_policy_bundle.py -i <controller_ip> -u <username> -o my_policy_bundle.zip
```

## Output

The script creates a ZIP file containing:

**Controller Data:**
- Terraform configuration files (`.tf`) for legacy firewall resources
- `gateway_details.json`: VPC and gateway information
- `any_webgroup.json`: Any-Web webgroup ID (if `-w` flag used)
- `vpc_route_tables.json`: Route table details (if `-r` flag used)

**CoPilot Data (when available):**
- `copilot_app_domains.json`: Microsegmentation app-domains data

## CoPilot Integration Features

- **Auto-Discovery**: Automatically finds CoPilot IP from controller
- **Graceful Failure**: Continues execution if CoPilot is unavailable
- **Enhanced Data**: Includes microsegmentation information for improved DCF translation
- **Flexible Options**: Skip or require CoPilot data as needed

## Requirements

- Python 3.6+
- Network access to Aviatrix Controller
- Network access to CoPilot (if using CoPilot integration)
- Valid Aviatrix credentials with appropriate permissions

## Error Handling

The script handles various failure scenarios gracefully:
- CoPilot not associated with controller
- CoPilot unreachable or authentication failures
- Network timeouts and connection errors
- Missing or invalid API endpoints

All failures are logged with informative messages, and the script continues with available data.