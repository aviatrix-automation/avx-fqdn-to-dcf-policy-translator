# Legacy Policy Bundle Exporter

This directory contains the exporter tool for collecting legacy Aviatrix firewall and FQDN policies from Aviatrix Controller and CoPilot.  The exporter script can optionally download the policy bundle for running the translation, or can send the policy bundle securely to Aviatrix for analysis.

## Files

- **`export_legacy_policy_bundle.py`**: Main export script with CoPilot integration
- **`copilot_auth_function_example.py`**: Reference implementation for CoPilot authentication
- **`requirements.txt`**: Python dependencies for the exporter
- **`cloudshell_install.sh`**: Automated installer for AWS/Azure CloudShell
- **`README.md`**: This documentation file


## Usage

![Demo](./images/legacy-policy-exporter.gif)

1. **Quick Install**: Copy the following command.
```bash
curl -fsSL https://raw.githubusercontent.com/aviatrix-automation/avx-fqdn-to-dcf-policy-translator/refs/heads/main/exporter/cloudshell_install.sh | bash
```
2. Open the AWS Console and open a Cloudshell session.
3. Copy and paste the installer command into Cloudshell and execute it.  This will setup the environment and download the exporter script.
4. Once the installer script has completed, it will show the IP address of the Cloudshell instance.  Add the CloudShell IP to the AWS Security Groups for your Aviatrix Controller and CoPilot.  This is necessary so that the exporter script can access the Controller and CoPilot from the Cloudshell environment.  Remember to remove this at after the exporter has completed.
5. Copy and paste the exporter commands into Cloudshell.  These are shown during the installer script execution, or can be copied and pasted from below:
```   
cd /home/cloudshell-user/aviatrix-policy-exporter
source venv/bin/activate
python export_legacy_policy_bundle.py
```
6. Follow the interactive wizard to input your Controller public IP, CoPilot public IP and credentials.  You will also need to add your customer ID if you want to share the exported information with Aviatrix.  Customer IDs need to be allow-listed by Aviatrix prior to secure upload.




## Detailed Instructions

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

### Secure API Upload
```bash
# Upload bundle to secure API and delete local file
python export_legacy_policy_bundle.py -i <controller_ip> -u <username> --customer-id customer-123

# Upload bundle but keep local file
python export_legacy_policy_bundle.py -i <controller_ip> -u <username> --customer-id customer-123 --keep-bundle

# Export only, don't upload
python export_legacy_policy_bundle.py -i <controller_ip> -u <username> --no-upload

# Use custom API endpoint
python export_legacy_policy_bundle.py -i <controller_ip> -u <username> --customer-id customer-123 --api-endpoint https://your-api.example.com/prod
```

### Interactive Mode
```bash
# Guided setup with prompts for all options
python export_legacy_policy_bundle.py --interactive
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

### Output Options

- **Local File**: By default, saves ZIP bundle to current directory
- **API Upload**: With `--customer-id`, securely uploads bundle to API
- **Dual Output**: Use `--keep-bundle` to upload AND keep local file
- **Local Only**: Use `--no-upload` to skip API upload

## CoPilot Integration Features

- **Auto-Discovery**: Automatically finds CoPilot IP from controller
- **Graceful Failure**: Continues execution if CoPilot is unavailable
- **Enhanced Data**: Includes microsegmentation information for improved DCF translation
- **Flexible Options**: Skip or require CoPilot data as needed

## API Upload Features

- **Secure Upload**: Uses presigned URLs for secure file transfer
- **Customer-Based**: Requires customer ID for access control
- **Flexible Storage**: Option to upload, keep local file, or both
- **Error Handling**: Graceful failure with local file retention
- **Custom Endpoints**: Support for different API environments

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