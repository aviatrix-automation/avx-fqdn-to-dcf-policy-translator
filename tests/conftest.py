"""
Shared test fixtures and configuration for the legacy-to-DCF policy translator tests.

This module provides pytest fixtures and configuration that can be reused
across all test modules.
"""

import json
import pytest
import pandas as pd
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import Mock

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from config import TranslationConfig


# Test data directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"
MINIMAL_DIR = FIXTURES_DIR / "minimal"
EXPECTED_DIR = FIXTURES_DIR / "expected_outputs"
MALFORMED_DIR = FIXTURES_DIR / "malformed"


@pytest.fixture(scope="session")
def test_config():
    """Create a test configuration with paths pointing to test fixtures."""
    config = TranslationConfig()
    config.input_dir = MINIMAL_DIR
    config.output_dir = Path("/tmp/test_output")
    config.debug_dir = Path("/tmp/test_debug")
    config.customer_name = "test_customer"
    config.validate_only = False
    config.debug = True
    return config


@pytest.fixture
def sample_fqdn_df():
    """Create a sample FQDN DataFrame for testing."""
    return pd.DataFrame([
        {
            "fqdn_tag": "test-enabled-tag",
            "fqdn_mode": "white",
            "fqdn_enabled": True,
            "gw_name": "test-gateway"
        },
        {
            "fqdn_tag": "test-disabled-tag", 
            "fqdn_mode": "white",
            "fqdn_enabled": False,
            "gw_name": None
        },
        {
            "fqdn_tag": "test-webgroup-tag",
            "fqdn_mode": "white", 
            "fqdn_enabled": True,
            "gw_name": "test-gateway-2"
        }
    ])


@pytest.fixture
def sample_fqdn_rules_df():
    """Create a sample FQDN rules DataFrame for testing."""
    return pd.DataFrame([
        # Webgroup rules (HTTP/HTTPS on 80/443)
        {
            "fqdn_tag_name": "test-webgroup-tag",
            "fqdn": "*.github.com",
            "protocol": "tcp",
            "port": "443"
        },
        {
            "fqdn_tag_name": "test-webgroup-tag",
            "fqdn": "api.example.com",
            "protocol": "http",
            "port": "80"
        },
        # Hostname rules (non-standard ports/protocols)
        {
            "fqdn_tag_name": "test-enabled-tag",
            "fqdn": "custom.internal.com",
            "protocol": "tcp",
            "port": "8080"
        },
        {
            "fqdn_tag_name": "test-enabled-tag",
            "fqdn": "*.monitoring.local",
            "protocol": "all",
            "port": ""
        },
        # Valid wildcard
        {
            "fqdn_tag_name": "test-enabled-tag",
            "fqdn": "*",
            "protocol": "tcp",
            "port": "443"
        },
        # Rule for disabled tag (should be filtered)
        {
            "fqdn_tag_name": "test-disabled-tag",
            "fqdn": "should.be.filtered.com",
            "protocol": "tcp",
            "port": "443"
        }
    ])


@pytest.fixture
def sample_gateway_details():
    """Load sample gateway details from test fixture."""
    with open(MINIMAL_DIR / "simple_gateway.json") as f:
        return json.load(f)


@pytest.fixture
def expected_results():
    """Load expected test results for validation."""
    with open(EXPECTED_DIR / "expected_results.json") as f:
        return json.load(f)


@pytest.fixture
def port_range_test_cases():
    """Load port range translation test cases."""
    with open(EXPECTED_DIR / "port_range_test_cases.json") as f:
        return json.load(f)


@pytest.fixture
def domain_validation_cases():
    """Load domain validation test cases."""
    with open(EXPECTED_DIR / "domain_validation_cases.json") as f:
        return json.load(f)


@pytest.fixture
def mock_logger():
    """Create a mock logger for testing."""
    return Mock()


@pytest.fixture
def empty_dataframe():
    """Create an empty DataFrame for testing edge cases."""
    return pd.DataFrame()


@pytest.fixture
def invalid_terraform_content():
    """Provide invalid Terraform content for error testing."""
    with open(MALFORMED_DIR / "invalid.tf") as f:
        return f.read()


@pytest.fixture
def invalid_json_content():
    """Provide invalid JSON content for error testing."""
    with open(MALFORMED_DIR / "invalid.json") as f:
        return f.read()


# Helper functions for test data manipulation
def create_test_smartgroup_df(names: List[str]) -> pd.DataFrame:
    """Create a test SmartGroup DataFrame with given names."""
    return pd.DataFrame([
        {
            "name": name,
            "selector": {"expressions": []},
            "type": "test"
        } for name in names
    ])


def create_test_policy_df(count: int) -> pd.DataFrame:
    """Create a test policy DataFrame with specified number of policies."""
    return pd.DataFrame([
        {
            "name": f"test-policy-{i}",
            "action": "allow",
            "src_smart_groups": [f"test-sg-{i}"],
            "dst_smart_groups": [f"test-dst-{i}"],
            "protocol": "TCP",
            "port_ranges": [{"from": 443, "to": 443}]
        } for i in range(count)
    ])


class MockFileSystem:
    """Mock file system operations for testing without actual file I/O."""
    
    def __init__(self):
        self.files = {}
        
    def add_file(self, path: str, content: str):
        """Add a file to the mock filesystem."""
        self.files[path] = content
        
    def read_file(self, path: str) -> str:
        """Read a file from the mock filesystem."""
        if path not in self.files:
            raise FileNotFoundError(f"No such file: {path}")
        return self.files[path]
        
    def file_exists(self, path: str) -> bool:
        """Check if file exists in mock filesystem."""
        return path in self.files


@pytest.fixture
def mock_filesystem():
    """Create a mock filesystem for testing."""
    return MockFileSystem()
