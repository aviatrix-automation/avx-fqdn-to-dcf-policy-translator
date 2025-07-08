"""
Domain constants and validation patterns for the legacy-to-DCF policy translator.
"""

import re
from dataclasses import dataclass
from typing import Set

# DCF 8.0 SNI domain validation regex pattern
DCF_SNI_DOMAIN_PATTERN = re.compile(r"^(\*|\*\.[-A-Za-z0-9_.]+|[-A-Za-z0-9_.]+)$")

# Data models for unsupported FQDN tracking
@dataclass
class UnsupportedFQDNRecord:
    """Record for tracking unsupported FQDN domains during translation."""
    fqdn_tag_name: str
    webgroup_name: str
    domain: str
    port: str
    protocol: str
    reason: str

# Protocol mappings and constants
PROTOCOL_MAPPINGS = {
    "all": "ANY",
    "any": "ANY",
    "tcp": "TCP",
    "udp": "UDP",
    "icmp": "ICMP",
    "http": "TCP",
    "https": "TCP",
}

# Action mappings
ACTION_MAPPINGS = {
    "allow": "PERMIT",
    "permit": "PERMIT",
    "deny": "DENY",
    "force-drop": "DENY",
    "drop": "DENY",
}

# FQDN mode mappings
FQDN_MODE_MAPPINGS = {
    "white": "permit",
    "black": "deny",
    "whitelist": "permit",
    "blacklist": "deny",
}

# Default port ranges for web traffic
DEFAULT_WEB_PORTS: Set[str] = {"80", "443"}

# Special port values
SPECIAL_PORTS = {"ALL": "ALL", "all": "ALL", "": "ALL"}

# DCF constraint constants
MAX_POLICY_NAME_LENGTH = 256
MAX_SMART_GROUP_NAME_LENGTH = 256
MAX_WEB_GROUP_NAME_LENGTH = 256
MAX_FQDN_DOMAIN_LENGTH = 253
MAX_CIDR_ENTRIES_PER_GROUP = 2000

# Default Smart Group IDs
DEFAULT_INTERNET_SG_ID = "def000ad-0000-0000-0000-000000000001"
DEFAULT_ANYWHERE_SG_ID = "def000ad-0000-0000-0000-000000000000"
DEFAULT_ANY_WEBGROUP_ID = "def000ad-0000-0000-0000-000000000002"

# Policy priority ranges
POLICY_PRIORITY_RANGES = {
    "l4_policies_start": 100,
    "hostname_policies_start": 200,
    "internet_policies_start": 300,
    "catch_all_policies_start": 65500,
}

# Gateway types and properties
GATEWAY_TYPES = {"hagw": "ha-gateway", "single": "single-gateway", "spoke": "spoke-gateway"}

# Supported file extensions
SUPPORTED_TF_EXTENSIONS = {".tf", ".tf.json"}
SUPPORTED_JSON_EXTENSIONS = {".json"}

# SmartGroup selector types
SMART_GROUP_SELECTOR_TYPES = {"cidr": "cidr", "vpc": "vpc", "hostname": "snifilter", "tag": "tag"}

# WebGroup selector types
WEB_GROUP_SELECTOR_TYPES = {"snifilter": "snifilter", "domain": "snifilter"}

# Resource name patterns
RESOURCE_NAME_PATTERNS = {
    "firewall": r"aviatrix_firewall",
    "firewall_policy": r"aviatrix_firewall_policy",
    "firewall_tag": r"aviatrix_firewall_tag",
    "fqdn": r"aviatrix_fqdn",
    "fqdn_tag_rule": r"aviatrix_fqdn_tag_rule",
    "smart_group": r"aviatrix_smart_group",
}

# Character replacement rules for DCF compatibility
INVALID_NAME_CHARS = {
    "/": "_",
    "\\": "_",
    ":": "_",
    "*": "_",
    "?": "_",
    '"': "_",
    "<": "_",
    ">": "_",
    "|": "_",
    " ": "_",
    "\t": "_",
    "\n": "_",
    "\r": "_",
    "~": "_",
    ".": "_",
}

# Terraform provider configuration
TERRAFORM_PROVIDER_CONFIG = {
    "required_version": ">=8.0",
    "source": "AviatrixSystems/aviatrix",
    "skip_version_validation": True,
}

# Validation patterns
IP_ADDRESS_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$")
IPV6_ADDRESS_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:/[0-9]{1,3})?$")
DOMAIN_NAME_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

# Domain validation patterns
DOMAIN_PATTERNS = {
    "dcf_sni": DCF_SNI_DOMAIN_PATTERN,
    "wildcard": re.compile(r"^\*\."),
    "valid_chars": re.compile(r"^[-A-Za-z0-9_.]+$"),
    "invalid_leading_chars": re.compile(r"^[-.]"),
    "invalid_trailing_chars": re.compile(r"[-.]$"),
}

# Common FQDN categories for analysis
COMMON_FQDN_CATEGORIES = {
    "cloud_providers": {
        "aws": [".amazonaws.com", ".aws.amazon.com"],
        "azure": [".azure.com", ".microsoft.com", ".microsoftonline.com"],
        "gcp": [".googleapis.com", ".gstatic.com", ".googleusercontent.com"],
    },
    "cdn_services": {
        "cloudflare": [".cloudflare.com"],
        "akamai": [".akamai.com", ".akamaitechnologies.com"],
        "fastly": [".fastly.com"],
    },
    "common_services": {
        "office365": [".office.com", ".outlook.com"],
        "google_workspace": [".google.com", ".gmail.com"],
        "salesforce": [".salesforce.com"],
    },
}

# Error messages
ERROR_MESSAGES = {
    "invalid_config": "Invalid configuration: {details}",
    "file_not_found": "Required file not found: {file_path}",
    "parsing_error": "Failed to parse {file_type}: {error}",
    "validation_failed": "Validation failed for {resource}: {errors}",
    "export_failed": "Failed to export {resource}: {error}",
    "dcf_incompatible": "Resource not compatible with DCF 8.0: {details}",
}

# Warning messages
WARNING_MESSAGES = {
    "empty_resource": "Resource {resource} is empty or not found",
    "deprecated_config": "Configuration {config} is deprecated",
    "potential_issue": "Potential issue detected in {resource}: {details}",
    "dcf_limitation": "DCF limitation may affect {resource}: {details}",
}

# Success messages
SUCCESS_MESSAGES = {
    "translation_complete": "Translation completed successfully",
    "export_complete": "Export completed: {count} {resource_type} exported",
    "validation_passed": "Validation passed for {resource}",
    "cleanup_complete": "Cleanup completed: {details}",
}
