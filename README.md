# Legacy to Distributed Cloud Firewall Policy Translator

This tool migrates legacy stateful firewall and FQDN egress policies to Aviatrix Distributed Cloud Firewall (DCF).

## Quick Start

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

```bash
python3 translator.py [options]
```

**Key Options:**
- `--internet-sg-id`: Internet security group ID (required)
- `--anywhere-sg-id`: Anywhere security group ID (required)
- `--default-web-port-ranges`: Default web port ranges (space-separated, can include ranges with commas)
- `--global-catch-all-action {PERMIT,DENY}`: Global catch-all action (default: PERMIT)
- `--config-path`: Path to configuration files (default: ./input)
- `--output-path`: Path for output files (default: ./output)
- `--debug-path`: Path for debug files (default: ./debug)
- `--loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}`: Set logging level

### 3. Deploy Configuration
Use Terraform to apply the generated configuration to your controller:

```bash
terraform init
terraform apply
```

**Recommendations:**
- Test in a lab environment first
- Start with `--global-catch-all-action PERMIT` and switch to `DENY` after validation
- Use `terraform destroy` for easy rollback if needed

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

### Object Translation

**SmartGroups Created From:**
- **Stateful Firewall Tags** → CIDR-type SmartGroups (preserves tag names)
- **Individual CIDRs** → Matched to existing tags or new SmartGroups named `cidr_{CIDR}-{mask}`  
- **VPCs** → SmartGroups with criteria "account, region, name" named `{vpcid}_{displayname}`

**WebGroups Created From:**
- **FQDN Tags** → Multiple WebGroups per tag based on port/protocol/action combinations
- **Naming Convention** → `{legacy_tag_name}_{protocol}_{port}_{action}`

### Policy Translation Phases

#### 1. L4/Stateful Firewall Translation
- **Deduplication**: Eliminates duplicate policies across primary/HA and source/destination gateways
- **Consolidation**: Merges policies with same source/destination/protocol but different ports
- **Optimization**: Reduces rule count while maintaining security posture

#### 2. FQDN Traffic Translation

**HTTP/HTTPS Traffic (WebGroups):**
- TCP traffic on ports 80, 443 → WebGroups for optimal web filtering
- Supports standard web protocols with enhanced performance

**Non-HTTP/HTTPS Traffic (FQDN SmartGroups):**
- All other protocols/ports → FQDN SmartGroups (DNS Hostname Resource Type)
- Supports SSH, SMTP, custom applications, any-protocol rules
- Real-time DNS resolution at policy enforcement

#### 3. Catch-All Policy Creation

The translator analyzes VPC configurations and creates appropriate catch-all rules:

- **Stateful FW with Default Deny** → Deny policies for those VPCs
- **Stateful FW with Default Allow** → Allow policies for those VPCs  
- **No Stateful FW Policy** → "Catch All Unknown" policies (requires manual review)
- **Global Catch-All** → Final rule with configurable PERMIT/DENY action

#### Special Cases
- **Discovery Mode VPCs**: Two policies created (web traffic + all other traffic)
- **NAT-Only VPCs**: Allow-all policy for public internet access when no FQDN tags present

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
