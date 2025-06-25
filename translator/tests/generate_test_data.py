#!/usr/bin/env python3
"""
Test data generator for the legacy-to-DCF policy translator unit tests.

This script creates minimal, focused test data for unit testing by extracting
and modifying samples from the existing real data files.
"""

import json
from pathlib import Path
from typing import Dict, List, Any


def create_minimal_fqdn_tf() -> str:
    """Create minimal FQDN test data covering key scenarios."""
    return '''
# Minimal FQDN test data for unit tests
resource "aviatrix_fqdn" "test_enabled" {
    fqdn_mode = "white"
    fqdn_enabled = true
    gw_filter_tag_list {
        gw_name = "test-gateway"
    }
    fqdn_tag = "test-enabled-tag"
    manage_domain_names = false
}

resource "aviatrix_fqdn" "test_disabled" {
    fqdn_mode = "white"
    fqdn_enabled = false
    fqdn_tag = "test-disabled-tag"
    manage_domain_names = false
}

resource "aviatrix_fqdn" "test_webgroup" {
    fqdn_mode = "white"
    fqdn_enabled = true
    fqdn_tag = "test-webgroup-tag"
    manage_domain_names = false
}
'''


def create_minimal_fqdn_rules_tf() -> str:
    """Create minimal FQDN rules covering different categorization scenarios."""
    return '''
# Webgroup rules (HTTP/HTTPS on 80/443)
resource "aviatrix_fqdn_tag_rule" "webgroup_rule_1" {
    fqdn_tag_name = "test-webgroup-tag"
    fqdn = "*.github.com"
    protocol = "tcp"
    port = "443"
}

resource "aviatrix_fqdn_tag_rule" "webgroup_rule_2" {
    fqdn_tag_name = "test-webgroup-tag"
    fqdn = "api.example.com"
    protocol = "http"
    port = "80"
}

# Hostname rules (non-standard ports/protocols)
resource "aviatrix_fqdn_tag_rule" "hostname_rule_1" {
    fqdn_tag_name = "test-enabled-tag"
    fqdn = "custom.internal.com"
    protocol = "tcp"
    port = "8080"
}

resource "aviatrix_fqdn_tag_rule" "hostname_rule_2" {
    fqdn_tag_name = "test-enabled-tag"
    fqdn = "*.monitoring.local"
    protocol = "all"
    port = ""
}

# DCF compatibility edge cases
resource "aviatrix_fqdn_tag_rule" "valid_wildcard" {
    fqdn_tag_name = "test-enabled-tag"
    fqdn = "*"
    protocol = "tcp"
    port = "443"
}

resource "aviatrix_fqdn_tag_rule" "invalid_wildcard" {
    fqdn_tag_name = "test-disabled-tag"
    fqdn = "*invalid-pattern"
    protocol = "tcp"
    port = "443"
}

# Rules for disabled FQDN tag (should be filtered out)
resource "aviatrix_fqdn_tag_rule" "disabled_rule" {
    fqdn_tag_name = "test-disabled-tag"
    fqdn = "should.be.filtered.com"
    protocol = "tcp"
    port = "443"
}
'''


def create_minimal_gateway_json() -> Dict[str, Any]:
    """Create minimal gateway details for testing."""
    return {
        "return": True,
        "results": [
            {
                "gw_name": "test-gateway",
                "vpc_name": "test-vpc",
                "vpc_id": "vpc-12345678",
                "vpc_region": "us-west-2",
                "cloud_type": 1,
                "fqdn_tags": ["test-enabled-tag"],
                "egress_control": "Enabled"
            },
            {
                "gw_name": "test-gateway-2",
                "vpc_name": "test-vpc-2", 
                "vpc_id": "vpc-87654321",
                "vpc_region": "us-east-1",
                "cloud_type": 1,
                "fqdn_tags": ["test-webgroup-tag"],
                "egress_control": "Enabled"
            }
        ]
    }


def create_expected_outputs() -> Dict[str, Any]:
    """Create expected output data for validation tests."""
    return {
        "expected_webgroups": [
            {
                "name": "test-webgroup-tag-webgroup",
                "selector": {
                    "expressions": [
                        {
                            "type": "domain_names",
                            "domain_names": ["*.github.com", "api.example.com"]
                        }
                    ]
                }
            }
        ],
        "expected_hostname_smartgroups": [
            {
                "name": "test-enabled-tag-hostname-sg",
                "selector": {
                    "expressions": [
                        {
                            "type": "fqdn",
                            "fqdn": "custom.internal.com",
                            "port": {"all": True},
                            "proto": "TCP"
                        },
                        {
                            "type": "fqdn", 
                            "fqdn": "*.monitoring.local",
                            "port": {"all": True},
                            "proto": "ANY"
                        }
                    ]
                }
            }
        ],
        "expected_policy_count": 3,
        "expected_categorization": {
            "webgroup_rules": 2,
            "hostname_rules": 3,  # Including valid wildcard
            "unsupported_rules": 0,
            "filtered_disabled_rules": 2
        }
    }


def create_port_range_test_cases() -> List[Dict[str, Any]]:
    """Create comprehensive port range translation test cases."""
    return [
        {"input": "80", "expected": [{"from": 80, "to": 80}]},
        {"input": "443", "expected": [{"from": 443, "to": 443}]},
        {"input": "8080-8090", "expected": [{"from": 8080, "to": 8090}]},
        {"input": "", "expected": "ALL"},
        {"input": ["80", "443"], "expected": [{"from": 80, "to": 80}, {"from": 443, "to": 443}]},
        {"input": ["8080-8090", "9000"], "expected": [{"from": 8080, "to": 8090}, {"from": 9000, "to": 9000}]},
    ]


def create_domain_validation_test_cases() -> Dict[str, List[str]]:
    """Create domain validation test cases for DCF 8.0 compatibility."""
    return {
        "valid_domains": [
            "*.github.com",
            "api.example.com", 
            "*",
            "sub.domain.co.uk",
            "simple.com",
            "*.amazonaws.com",
            "localhost"
        ],
        "invalid_domains": [
            "*github.com",      # Wildcard without dot
            "domain.*",         # Wildcard at end
            "*.*.domain.com",   # Multiple wildcards
            "*domain*.com",     # Wildcard in middle
            "",                 # Empty string
            "domain .com",      # Space in domain
            "domain..com",      # Double dots
        ]
    }


def generate_all_test_data(output_dir: Path):
    """Generate all test data files in the specified directory."""
    output_dir = Path(output_dir)
    
    # Create directory structure
    minimal_dir = output_dir / "minimal"
    edge_cases_dir = output_dir / "edge_cases"
    expected_dir = output_dir / "expected_outputs"
    
    minimal_dir.mkdir(parents=True, exist_ok=True)
    edge_cases_dir.mkdir(parents=True, exist_ok=True)
    expected_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate minimal test files
    (minimal_dir / "simple_fqdn.tf").write_text(create_minimal_fqdn_tf())
    (minimal_dir / "simple_rules.tf").write_text(create_minimal_fqdn_rules_tf())
    
    with open(minimal_dir / "simple_gateway.json", "w") as f:
        json.dump(create_minimal_gateway_json(), f, indent=2)
    
    # Generate expected outputs
    with open(expected_dir / "expected_results.json", "w") as f:
        json.dump(create_expected_outputs(), f, indent=2)
    
    with open(expected_dir / "port_range_test_cases.json", "w") as f:
        json.dump(create_port_range_test_cases(), f, indent=2)
    
    with open(expected_dir / "domain_validation_cases.json", "w") as f:
        json.dump(create_domain_validation_test_cases(), f, indent=2)
    
    # Create empty/malformed files for error testing
    malformed_dir = output_dir / "malformed"
    malformed_dir.mkdir(exist_ok=True)
    
    (malformed_dir / "empty.tf").write_text("")
    (malformed_dir / "invalid.tf").write_text("invalid hcl content {{{")
    (malformed_dir / "invalid.json").write_text('{"invalid": json,}')
    
    print(f"✅ Generated comprehensive test data in {output_dir}")
    print(f"   - Minimal test files: {len(list(minimal_dir.glob('*')))} files")
    print(f"   - Expected outputs: {len(list(expected_dir.glob('*')))} files") 
    print(f"   - Malformed files: {len(list(malformed_dir.glob('*')))} files")


if __name__ == "__main__":
    # Generate test data in the tests/fixtures directory
    script_dir = Path(__file__).parent
    fixtures_dir = script_dir / "fixtures"
    
    generate_all_test_data(fixtures_dir)
