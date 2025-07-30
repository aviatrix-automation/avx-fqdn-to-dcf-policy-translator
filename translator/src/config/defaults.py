"""
Default configuration values and constants for the legacy-to-DCF policy translator.
"""

import os
from pathlib import Path
from typing import Dict, Optional

# File path defaults
DEFAULT_INPUT_DIR = "input"
DEFAULT_OUTPUT_DIR = "output"
DEFAULT_DEBUG_DIR = "debug"

# File name patterns
TERRAFORM_FILE_PATTERNS = {
    "firewall": "firewall.tf",
    "firewall_policy": "firewall_policy.tf",
    "firewall_tag": "firewall_tag.tf",
    "fqdn": "fqdn.tf",
    "fqdn_tag_rule": "fqdn_tag_rule.tf",
    "smart_group": "smart_group.tf",
    "gateway_details": "gateway_details.json",
    "copilot_app_domains": "copilot_app_domains.json",
}

# Output file names
OUTPUT_FILES = {
    "smart_groups": "aviatrix_smart_group.tf.json",
    "web_groups": "aviatrix_web_group.tf.json",
    "dcf_policies": "aviatrix_distributed_firewalling_policy_list.tf.json",
    "main_tf": "main.tf",
    "full_policy_list": "full_policy_list.csv",
    "smart_groups_csv": "smartgroups.csv",
    "unsupported_fqdn": "unsupported_fqdn_rules.csv",
    "removed_duplicates": "removed_duplicate_policies.csv",
}

# Debug file names
DEBUG_FILES = {
    "clean_policies": "clean_policies.csv",
    "clean_fqdn": "clean_fqdn.csv",
    "clean_fqdn_hostnames": "clean_fqdn_hostnames.csv",
    "clean_fqdn_webgroups": "clean_fqdn_webgroups.csv",
    "removed_duplicates": "removed_duplicate_policies.csv",
}

# DCF validation constraints
DCF_CONSTRAINTS = {
    "max_policy_name_length": 256,
    "max_smart_group_name_length": 256,
    "max_web_group_name_length": 256,
    "supported_port_protocols": ["tcp", "udp", "icmp"],
    "max_fqdn_domain_length": 253,
    "max_cidr_entries_per_group": 2000,
}

# Default policy priorities
POLICY_PRIORITIES = {
    "l4_policies": 100,
    "hostname_policies": 500,
    "webgroup_policies": 1000,
    "catch_all_deny": 3000,
    # Legacy support - remove in future versions
    "internet_policies": 1000
}

# FQDN Source IP List Feature Configuration
FQDN_SOURCE_IP_CONFIG = {
    "enable_advanced_translation": True,  # Enable asset-based translation
    "simple_smartgroup_suffix": "_source_ips",  # Suffix for simple mode SmartGroups
    "asset_smartgroup_suffix": "_asset",  # Suffix for asset-based SmartGroups
    "policy_priority_offset": 50,  # Priority offset for source IP policies
}

# Environment variable mappings
ENV_VAR_MAPPINGS = {
    "input_dir": "TRANSLATOR_INPUT_DIR",
    "output_dir": "TRANSLATOR_OUTPUT_DIR",
    "debug_dir": "TRANSLATOR_DEBUG_DIR",
    "enable_debug": "TRANSLATOR_DEBUG_ENABLED",
    "force_overwrite": "TRANSLATOR_FORCE_OVERWRITE",
    "validate_only": "TRANSLATOR_VALIDATE_ONLY",
    "fqdn_source_ip_advanced": "TRANSLATOR_FQDN_SOURCE_IP_ADVANCED",
}

# Character replacements for DCF compatibility
INVALID_CHARS_REPLACEMENT = {
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
}


def get_env_value(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get environment variable value with optional default."""
    env_key = ENV_VAR_MAPPINGS.get(key, key.upper())
    return os.getenv(env_key, default)


def get_default_paths() -> Dict[str, Path]:
    """Get default directory paths relative to project root."""
    project_root = Path(__file__).parent.parent.parent
    return {
        "input_dir": project_root / DEFAULT_INPUT_DIR,
        "output_dir": project_root / DEFAULT_OUTPUT_DIR,
        "debug_dir": project_root / DEFAULT_DEBUG_DIR,
    }
