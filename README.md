# Legacy to Distributed Cloud Firewall Policy Translator

This tool migrates legacy stateful firewall and FQDN egress policies to Aviatrix Distributed Cloud Firewall (DCF) using a modular architecture.

## Architecture Overview

The translator uses a modular architecture for improved maintainability, testing, and extensibility:

### Core Components
- **`src/main.py`**: Primary entry point with comprehensive CLI options
- **`src/config/`**: Configuration management and default values
- **`src/data/`**: Data loading, processing, cleaning, and export functionality
- **`src/translation/`**: Policy translation engines (L4, FQDN, SmartGroups, WebGroups)
- **`src/analysis/`**: Policy validation, FQDN analysis, and translation reporting
- **`src/utils/`**: Utility functions and helper methods
- **`src/domain/`**: Domain models, constants, and validation logic

### Legacy Script
- **`translator.py`**: Original monolithic script (maintained for backward compatibility)
- Both entry points produce identical results

## Quick Start

### Primary Entry Point
```bash
python src/main.py [options]
```

### Legacy Entry Point (Alternative)
```bash
python translator.py [options]
```

## Important Topology Requirements for DCF 8.0

### Unsupported Topologies
The following legacy topologies are **not supported** in DCF 8.0:

- **Centralized Egress**: Will be available in DCF 8.1
- **Standalone FQDN Gateways**: DCF requires "spoke" gateways for operation

### Migration from Standalone FQDN Gateways

If your environment uses standalone FQDN gateways, you must migrate to spoke gateways. The general recommendation is:

1. **Migrate policies first** using this translator tool (policies won't take effect until gateway migration)
2. **Deploy spoke gateways** alongside existing FQDN gateways
3. **Switch traffic to spoke gateways**:
   - Disable the FQDN tag on the legacy gateway
   - Enable Single IP SNAT on the spoke gateway
   - This transition will cause a brief traffic outage between disable and re-enable.
4. **Fallback option**: If needed, disable SNAT and re-enable the FQDN tag
5. **Complete migration**: When comfortable, decommission the FQDN gateways

> **Note**: Spoke gateways can be deployed in parallel with FQDN gateways to minimize downtime during the transition.

### 1. Export Legacy Policy Bundle
Run the export script against your controller to generate a ZIP file containing all legacy policies:

```bash
python3 export_legacy_policy_bundle.py -i <controller_ip> -u <username> [-p <password>] [-o <output_file>] [-w]
```

**Options:**
- `-i, --controller_ip`: Controller IP address (required)
- `-u, --username`: Username (required)  
- `-p, --password`: Password (optional, will prompt if not provided)
- `-o, --output`: Output file name (optional)
- `-w, --any_web`: Download the Any Webgroup ID (requires controller v7.1+)

### 2. Translate Policies
1. Create required directories: `./input`, `./output`, and optionally `./debug`
2. Extract the exported policy bundle into the `./input` directory
3. Obtain the "Any Webgroup" ID from your target controller (available in v7.1+)
4. Run the translator:

**Primary Entry Point:**
```bash
# Basic translation with default settings
python src/main.py

# Custom directories and customer context
python src/main.py --input-dir ./input --output-dir ./output --customer-name "Example Corp"

# Debug mode with detailed logging
python src/main.py --debug --loglevel INFO

# Validation only (no output generation)
python src/main.py --validate-only --loglevel INFO

# Custom DCF configuration
python src/main.py --global-catch-all-action DENY --any-webgroup-id "custom-webgroup-id"
```

**Legacy Entry Point (Alternative):**
```bash
python translator.py [options]
```

**Key Options:**

*Directory Configuration:*
- `--input-dir`: Path to input files (default: ./input)
- `--output-dir`: Path for output files (default: ./output)
- `--debug-dir`: Path for debug files (default: ./debug)

*Processing Options:*
- `--debug`: Enable debug mode with detailed output and debug files
- `--force`: Force overwrite existing output files
- `--validate-only`: Only validate input files without generating output
- `--customer-name`: Customer name for naming context

*DCF Configuration:*
- `--internet-sg-id`: Internet security group ID (default: def000ad-0000-0000-0000-000000000001)
- `--anywhere-sg-id`: Anywhere security group ID (default: def000ad-0000-0000-0000-000000000000)
- `--any-webgroup-id`: Any webgroup ID (default: def000ad-0000-0000-0000-000000000002)
- `--default-web-port-ranges`: Default web port ranges (default: 80 443)
- `--global-catch-all-action {PERMIT,DENY}`: Global catch-all action (default: PERMIT)

*Logging:*
- `--loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}`: Set logging level (default: WARNING)

### 3. Deploy Configuration
Use Terraform to apply the generated configuration to your controller:

```bash
terraform init
terraform apply
```

**Recommendations:**
- **Topology Assessment**: Verify your environment is compatible with DCF 8.0 (see topology requirements above)
- **Gateway Migration**: If using standalone FQDN gateways, plan for spoke gateway deployment
- **Testing**: Test in a lab environment first
- **Catch-All Policy**: Start with `--global-catch-all-action PERMIT` and switch to `DENY` after validation
- **Rollback Plan**: Use `terraform destroy` for easy rollback if needed

## Generated Output Files

The translator creates several files for DCF configuration and policy review:

**Terraform Configuration:**
- `aviatrix_distributed_firewall_policy_list.tf.json`: DCF rule list
- `aviatrix_smart_group.tf.json`: SmartGroups (CIDR, VPC, and FQDN-based)
- `aviatrix_web_group.tf.json`: WebGroups for HTTP/HTTPS traffic
- `main.tf`: Complete Terraform configuration

**Review Files:**
- `smartgroups.csv`: SmartGroup configuration summary
- `full_policy_list.csv`: Complete translated policy list
- `unsupported_fqdn_rules.csv`: Rules requiring manual configuration
- `removed_duplicate_policies.csv`: Optimized duplicate policies

### Monitoring Translation Progress

Pay attention to log output during translation:
- **WARNING**: DCF 8.0 incompatible SNI domains filtered out  
- **INFO**: Count of domains retained for each webgroup

Example:
```
WARNING:root:Filtered 11 DCF 8.0 incompatible SNI domains for webgroup 'ws-prod-egress-whitelist_permit_tcp_443'
INFO:root:Retained 215 DCF 8.0 compatible domains for webgroup 'ws-prod-egress-whitelist_permit_tcp_443'
```

## Translation Process

### Modular Translation Architecture

The new architecture separates concerns into specialized components:

**Data Processing Pipeline:**
1. **Configuration Loading** (`src/data/loaders.py`): Loads and validates input files
2. **Data Cleaning** (`src/data/processors.py`): Unified character cleaning and deduplication
3. **SmartGroup Creation** (`src/translation/smartgroups.py`): CIDR, VPC, and hostname SmartGroups
4. **Policy Translation** (`src/translation/policies.py`): L4, Internet, and Catch-all policies
5. **FQDN Processing** (`src/translation/fqdn_handlers.py`): WebGroups and hostname policies
6. **Data Export** (`src/data/exporters.py`): Terraform JSON generation

**Validation & Analysis:**
- **Policy Validation** (`src/analysis/policy_validators.py`): Rule consistency checks
- **FQDN Analysis** (`src/analysis/fqdn_analysis.py`): Domain compatibility validation
- **Translation Reporting** (`src/analysis/translation_reporter.py`): Comprehensive reports

### Object Translation

**SmartGroups Created From:**
- **Stateful Firewall Tags** → CIDR-type SmartGroups (preserves tag names)
- **Individual CIDRs** → Matched to existing tags or new SmartGroups named `cidr_{CIDR}-{mask}`  
- **VPCs** → SmartGroups with criteria "account, region, name" named `{vpcid}_{displayname}`
- **FQDN Hostnames** → DNS hostname SmartGroups for non-HTTP/HTTPS traffic

**WebGroups Created From:**
- **FQDN Tags** → Multiple WebGroups per tag based on port/protocol/action combinations
- **Naming Convention** → `{legacy_tag_name}_{protocol}_{port}_{action}`
- **Character Cleaning** → Consistent handling of special characters (e.g., `~~` → `_`)

### Policy Translation Phases

#### 1. L4/Stateful Firewall Translation (`L4PolicyBuilder`)
- **Deduplication**: Eliminates duplicate policies across primary/HA and source/destination gateways
- **Consolidation**: Merges policies with same source/destination/protocol but different ports
- **Optimization**: Reduces rule count while maintaining security posture
- **Character Consistency**: Unified SmartGroup reference naming

#### 2. FQDN Traffic Translation (`FQDNHandler`)

**HTTP/HTTPS Traffic (WebGroups):**
- TCP traffic on ports 80, 443 → WebGroups for optimal web filtering
- Supports standard web protocols with enhanced performance
- DCF 8.0 SNI domain validation and automatic filtering

**Non-HTTP/HTTPS Traffic (FQDN SmartGroups):**
- All other protocols/ports → FQDN SmartGroups (DNS Hostname Resource Type)
- Supports SSH, SMTP, custom applications, any-protocol rules
- Real-time DNS resolution at policy enforcement

#### 3. Catch-All Policy Creation (`CatchAllPolicyBuilder`)

The translator analyzes VPC configurations and creates appropriate catch-all rules:

- **Stateful FW with Default Deny** → Deny policies for those VPCs
- **Stateful FW with Default Allow** → Allow policies for those VPCs  
- **No Stateful FW Policy** → "Catch All Unknown" policies (requires manual review)
- **Global Catch-All** → Final rule with configurable PERMIT/DENY action

#### Special Cases
- **Discovery Mode VPCs**: Two policies created (web traffic + all other traffic)
- **NAT-Only VPCs**: Allow-all policy for public internet access when no FQDN tags present
- **Character Cleaning**: Consistent `~~` → `_` conversion across all components

### Key Features
- All rules except global catch-all are set to log by default
- Global catch-all defaults to ALLOW (change to DENY after validation)
- Disabled tags create WebGroups but are not used in policies

## Important Considerations

### DCF 8.0 SNI Domain Validation
The translator includes automatic validation for DCF 8.0 SNI domain compatibility:

**Supported Domain Formats:**
- Exact wildcard: `*`
- Wildcard with subdomain: `*.domain.com` (requires dot after asterisk)
- Regular domain: `domain.com`

**Validation Pattern:** `\*|\*\.[-A-Za-z0-9_.]+|[-A-Za-z0-9_.]+`

**Automatic Filtering:**
- Malformed domains are automatically filtered out
- WARNING logs generated for filtered domains
- Examples filtered: `*awsapps.com` (missing dot after asterisk)
- Examples retained: `*.protection.office.com`, `example.com`, `*`

**Benefits:**
- Prevents terraform apply failures
- Maintains DCF 8.0 compatibility
- Clear visibility via logging

### FQDN SmartGroup Features

**DNS Hostname SmartGroups:**
- Enable filtering of non-HTTP/HTTPS traffic using FQDNs
- Real-time DNS resolution at policy enforcement
- Support for SSH, SMTP, custom applications, any-protocol rules

**Requirements:**
- Must use fully qualified domain names (FQDNs)
- Valid DNS hostname characters only
- No wildcard support
- Uses gateway's configured DNS server (management DNS by default)

**Usage Guidelines:**
- **WebGroups**: HTTP/HTTPS traffic on ports 80/443 (optimal performance)
- **FQDN SmartGroups**: All other traffic types

**Translation Logic:**
1. TCP ports 80/443 → WebGroups (optimal for web traffic)
2. All other traffic → FQDN SmartGroups (comprehensive protocol support)

### Migration Best Practices
- Test in lab environment before production deployment
- Start with global catch-all PERMIT, switch to DENY after validation
- Review generated CSV files for policy verification
- Use `terraform destroy` for easy rollback
- All FQDN rules are automatically translated - no manual intervention required
