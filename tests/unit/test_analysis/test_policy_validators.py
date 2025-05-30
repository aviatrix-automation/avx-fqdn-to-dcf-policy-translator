"""
Unit tests for policy validation module.

Tests the ValidationResult dataclass and PolicyValidator class for analyzing
legacy firewall policies and identifying translation issues.
"""

import pytest
import pandas as pd
from unittest.mock import Mock, patch, MagicMock
from typing import Set, Dict

from src.analysis.policy_validators import (
    ValidationResult,
    PolicyValidator
)


class TestValidationResult:
    """Test the ValidationResult dataclass."""

    def test_validation_result_creation(self):
        """Test creating ValidationResult with all fields."""
        unused_tags = {"unused1", "unused2"}
        single_cidr_tags = {"192.168.1.0/24": "cidr_tag1"}
        warnings = ["Warning 1", "Warning 2"]
        errors = ["Error 1"]
        
        result = ValidationResult(
            total_policies=100,
            issues_found=25,
            stateless_issues=5,
            unused_tags=unused_tags,
            single_cidr_tags=single_cidr_tags,
            duplicate_policies=10,
            validation_warnings=warnings,
            validation_errors=errors
        )

        assert result.total_policies == 100
        assert result.issues_found == 25
        assert result.stateless_issues == 5
        assert result.unused_tags == unused_tags
        assert result.single_cidr_tags == single_cidr_tags
        assert result.duplicate_policies == 10
        assert result.validation_warnings == warnings
        assert result.validation_errors == errors


class TestPolicyValidator:
    """Test the PolicyValidator class."""

    def test_init(self):
        """Test initialization of PolicyValidator."""
        validator = PolicyValidator()
        assert hasattr(validator, 'logger')

    def test_eval_stateless_alerts_basic(self):
        """Test evaluation of stateless policy issues."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "protocol": ["udp", "tcp", "all", "udp"],
            "port": ["", "80", "", "53"],
            "action": ["allow", "allow", "force-drop", "allow"]
        })
        
        result = validator.eval_stateless_alerts(fw_policy_df)
        
        # Should find 2 stateless issues: UDP with no port, and ALL with no port
        assert len(result) == 2
        assert result.iloc[0]["protocol"] in ["udp", "all"]
        assert result.iloc[1]["protocol"] in ["udp", "all"]
        assert all(result["port"] == "")

    def test_eval_stateless_alerts_no_issues(self):
        """Test stateless evaluation when no issues exist."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "protocol": ["tcp", "udp", "tcp"],
            "port": ["80", "53", "443"],
            "action": ["allow", "allow", "deny"]
        })
        
        result = validator.eval_stateless_alerts(fw_policy_df)
        
        # Should find no stateless issues
        assert len(result) == 0

    def test_eval_stateless_alerts_empty_dataframe(self):
        """Test stateless evaluation with empty DataFrame."""
        validator = PolicyValidator()

        empty_df = pd.DataFrame(columns=[
            "protocol", "port", "action"  # Add required columns for empty DataFrame
        ])
        result = validator.eval_stateless_alerts(empty_df)
        
        assert len(result) == 0

    def test_eval_unused_fw_tags_basic(self):
        """Test identification of unused firewall tags."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "src_ip": ["tag1", "192.168.1.1", "tag2"],
            "dst_ip": ["tag2", "tag3", "192.168.2.1"]
        })
        
        fw_tag_df = pd.DataFrame({
            "firewall_tag": ["tag1", "tag2", "tag3", "unused_tag", "another_unused"]
        })
        
        filtered_df, unused_tags = validator.eval_unused_fw_tags(fw_policy_df, fw_tag_df)
        
        # Should identify unused tags
        assert unused_tags == {"unused_tag", "another_unused"}
        
        # Filtered DataFrame should not contain unused tags
        assert "unused_tag" not in filtered_df["firewall_tag"].values
        assert "another_unused" not in filtered_df["firewall_tag"].values
        assert len(filtered_df) == 3  # tag1, tag2, tag3

    def test_eval_unused_fw_tags_all_used(self):
        """Test when all firewall tags are used."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "src_ip": ["tag1", "tag2"],
            "dst_ip": ["tag3", "tag1"]
        })
        
        fw_tag_df = pd.DataFrame({
            "firewall_tag": ["tag1", "tag2", "tag3"]
        })
        
        filtered_df, unused_tags = validator.eval_unused_fw_tags(fw_policy_df, fw_tag_df)
        
        # Should find no unused tags
        assert unused_tags == set()
        assert len(filtered_df) == 3

    def test_eval_single_cidr_tag_match_basic(self):
        """Test single CIDR tag matching and replacement."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "src_ip": ["192.168.1.0/24", "tag1", "192.168.2.0/24"],
            "dst_ip": ["tag2", "192.168.1.0/24", "10.0.0.0/8"]
        })
        
        fw_tag_df = pd.DataFrame({
            "firewall_tag": ["internal_tag", "dmz_tag", "external_tag"],
            "cidr_list": [
                {"cidr": "192.168.1.0/24"},
                {"cidr": "192.168.2.0/24"},
                [{"cidr": "10.0.0.1/32"}, {"cidr": "10.0.0.2/32"}]  # Multiple CIDRs
            ]
        })
        
        updated_df, mappings = validator.eval_single_cidr_tag_match(fw_policy_df, fw_tag_df)
        
        # Should map single CIDR entries to named tags
        expected_mappings = {
            "192.168.1.0/24": "internal_tag",
            "192.168.2.0/24": "dmz_tag"
        }
        assert mappings == expected_mappings
        
        # Should update policy references
        assert "internal_tag" in updated_df["src_ip"].values
        assert "dmz_tag" in updated_df["src_ip"].values

    def test_eval_single_cidr_tag_match_no_single_cidrs(self):
        """Test single CIDR matching when no single CIDRs exist."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "src_ip": ["tag1", "tag2"],
            "dst_ip": ["tag3", "tag1"]
        })
        
        fw_tag_df = pd.DataFrame({
            "firewall_tag": ["tag1", "tag2", "tag3"],
            "cidr_list": [
                [{"cidr": "192.168.1.1/32"}, {"cidr": "192.168.1.2/32"}],  # Multiple
                [{"cidr": "192.168.2.1/32"}],  # List with single item, not dict
                "not_a_dict"  # Invalid format
            ]
        })
        
        updated_df, mappings = validator.eval_single_cidr_tag_match(fw_policy_df, fw_tag_df)
        
        # Should find no mappings
        assert mappings == {}
        # DataFrame should be unchanged
        pd.testing.assert_frame_equal(updated_df, fw_policy_df)

    def test_identify_duplicate_policies_basic(self):
        """Test identification and removal of duplicate policies."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "src_ip": ["192.168.1.1", "192.168.1.1", "192.168.2.1"],
            "dst_ip": ["10.0.0.1", "10.0.0.1", "10.0.0.2"],
            "protocol": ["tcp", "tcp", "tcp"],
            "port": ["80", "80", "443"],
            "action": ["allow", "allow", "allow"],
            "policy_name": ["policy1", "policy1_dup", "policy2"]  # Different names but same rule
        })
        
        deduplicated_df, duplicate_count = validator.identify_duplicate_policies(fw_policy_df)
        
        # Should find 1 duplicate
        assert duplicate_count == 1
        assert len(deduplicated_df) == 2
        
        # Should keep the first occurrence
        assert "policy1" in deduplicated_df["policy_name"].values
        assert "policy1_dup" not in deduplicated_df["policy_name"].values

    def test_identify_duplicate_policies_no_duplicates(self):
        """Test duplicate identification when no duplicates exist."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "src_ip": ["192.168.1.1", "192.168.1.2"],
            "dst_ip": ["10.0.0.1", "10.0.0.2"],
            "protocol": ["tcp", "udp"],
            "port": ["80", "53"],
            "action": ["allow", "allow"]
        })
        
        deduplicated_df, duplicate_count = validator.identify_duplicate_policies(fw_policy_df)
        
        # Should find no duplicates
        assert duplicate_count == 0
        assert len(deduplicated_df) == 2

    def test_validate_protocol_port_combinations_valid(self):
        """Test protocol/port validation with valid combinations."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "protocol": ["tcp", "udp", "icmp"],
            "port": ["80", "53", ""],  # ICMP should not have port
        })
        
        warnings = validator.validate_protocol_port_combinations(fw_policy_df)
        
        # Should find no warnings for valid combinations
        assert len(warnings) == 0

    def test_validate_protocol_port_combinations_invalid_tcp_ports(self):
        """Test protocol/port validation with invalid TCP ports."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "protocol": ["tcp", "tcp", "tcp", "tcp"],
            "port": ["70000", "0", "abc", "100-50"],  # All invalid
        })
        
        warnings = validator.validate_protocol_port_combinations(fw_policy_df)
        
        # Should find warnings for all invalid TCP ports
        assert len(warnings) == 4
        assert any("70000" in warning for warning in warnings)
        assert any("abc" in warning for warning in warnings)
        assert any("100-50" in warning for warning in warnings)

    def test_validate_protocol_port_combinations_icmp_with_ports(self):
        """Test protocol/port validation for ICMP with ports."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "protocol": ["icmp", "icmp", "icmp"],
            "port": ["", "80", "any"],  # Only first is valid
        })
        
        warnings = validator.validate_protocol_port_combinations(fw_policy_df)
        
        # Should find warning about ICMP policies with ports
        assert len(warnings) == 1
        assert "ICMP policies with port specifications" in warnings[0]

    def test_validate_protocol_port_combinations_valid_tcp_ranges(self):
        """Test protocol/port validation with valid TCP port ranges."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "protocol": ["tcp", "tcp", "tcp"],
            "port": ["80-90", "1-65535", "any"],
        })
        
        warnings = validator.validate_protocol_port_combinations(fw_policy_df)
        
        # Should find no warnings for valid ranges
        assert len(warnings) == 0

    @patch('utils.data_processing.is_ipv4')
    def test_validate_ip_addresses_valid(self, mock_is_ipv4):
        """Test IP address validation with valid addresses."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "src_ip": ["192.168.1.1", "tag1"],
            "dst_ip": ["10.0.0.1", "tag2"]
        })
        
        fw_tag_df = pd.DataFrame({
            "firewall_tag": ["tag1", "tag2"],
            "cidr_list": [
                {"cidr": "192.168.1.0/24"},
                [{"cidr": "10.0.0.0/8"}]
            ]
        })
        
        # Mock valid IP addresses
        mock_is_ipv4.return_value = True
        
        warnings = validator.validate_ip_addresses(fw_policy_df, fw_tag_df)
        
        # Should find no warnings
        assert len(warnings) == 0

    @patch('utils.data_processing.is_ipv4')
    def test_validate_ip_addresses_invalid_policy_ips(self, mock_is_ipv4):
        """Test IP address validation with invalid IPs in policies."""
        validator = PolicyValidator()

        fw_policy_df = pd.DataFrame({
            "src_ip": ["invalid_ip", "unknown_tag"],
            "dst_ip": ["192.168.1.1", "another_unknown_tag"]
        })

        fw_tag_df = pd.DataFrame({
            "firewall_tag": ["known_tag"],
            "cidr_list": [{"cidr": "192.168.1.0/24"}]
        })

        def mock_is_ipv4_side_effect(ip):
            return ip == "192.168.1.1"

        mock_is_ipv4.side_effect = mock_is_ipv4_side_effect

        warnings = validator.validate_ip_addresses(fw_policy_df, fw_tag_df)

        # Should find warnings for:
        # 1. invalid_ip in src_ip of policy 0
        # 2. unknown_tag in src_ip of policy 1 (not a valid tag)
        # 3. another_unknown_tag in dst_ip of policy 1 (not a valid tag)
        # 4. Invalid CIDR in tag known_tag (192.168.1.0/24 fails mock validation)
        assert len(warnings) == 4
        assert any("invalid_ip" in warning for warning in warnings)
        assert any("unknown_tag" in warning for warning in warnings)

    @patch('utils.data_processing.is_ipv4')
    def test_validate_ip_addresses_invalid_tag_cidrs(self, mock_is_ipv4):
        """Test IP address validation with invalid CIDRs in tags."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "src_ip": ["tag1"],
            "dst_ip": ["tag2"]
        })
        
        fw_tag_df = pd.DataFrame({
            "firewall_tag": ["tag1", "tag2", "tag3"],
            "cidr_list": [
                {"cidr": "invalid_cidr"},
                [{"cidr": "another_invalid_cidr"}],
                "not_a_list_or_dict"
            ]
        })
        
        # Mock invalid CIDRs
        mock_is_ipv4.return_value = False
        
        warnings = validator.validate_ip_addresses(fw_policy_df, fw_tag_df)
        
        # Should find warnings for invalid CIDRs
        assert len(warnings) == 2
        assert any("invalid_cidr" in warning for warning in warnings)
        assert any("another_invalid_cidr" in warning for warning in warnings)

    def test_perform_comprehensive_validation_empty_policies(self):
        """Test comprehensive validation with empty policies DataFrame."""
        validator = PolicyValidator()
        
        empty_df = pd.DataFrame()
        fw_tag_df = pd.DataFrame({
            "firewall_tag": ["tag1"],
            "cidr_list": [{"cidr": "192.168.1.0/24"}]
        })
        
        result = validator.perform_comprehensive_validation(empty_df, fw_tag_df)
        
        assert isinstance(result, ValidationResult)
        assert result.total_policies == 0
        assert result.issues_found == 0
        assert "No firewall policies found" in result.validation_warnings

    def test_perform_comprehensive_validation_full_flow(self):
        """Test comprehensive validation with full flow."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "src_ip": ["192.168.1.1", "192.168.1.1", "tag1"],
            "dst_ip": ["10.0.0.1", "10.0.0.1", "unused_tag"],
            "protocol": ["udp", "udp", "tcp"],
            "port": ["", "", "80"],  # First two are stateless issues
            "action": ["allow", "allow", "allow"]
        })
        
        fw_tag_df = pd.DataFrame({
            "firewall_tag": ["tag1", "unused_tag", "single_cidr_tag"],
            "cidr_list": [
                [{"cidr": "192.168.1.1/32"}, {"cidr": "192.168.1.2/32"}],  # Multiple CIDRs
                {"cidr": "192.168.2.0/24"},  # Unused
                {"cidr": "10.0.0.0/8"}  # Single CIDR
            ]
        })
        
        # Mock the individual methods to control their behavior
        with patch.object(validator, 'eval_stateless_alerts') as mock_stateless:
            with patch.object(validator, 'eval_unused_fw_tags') as mock_unused:
                with patch.object(validator, 'eval_single_cidr_tag_match') as mock_single_cidr:
                    with patch.object(validator, 'identify_duplicate_policies') as mock_duplicates:
                        with patch.object(validator, 'validate_protocol_port_combinations') as mock_protocol:
                            with patch.object(validator, 'validate_ip_addresses') as mock_ip:
                                
                                # Setup mock returns
                                mock_stateless.return_value = pd.DataFrame([{"issue": "stateless"}])
                                mock_unused.return_value = (fw_tag_df.iloc[:2], {"unused_tag"})
                                mock_single_cidr.return_value = (fw_policy_df, {"10.0.0.0/8": "single_cidr_tag"})
                                mock_duplicates.return_value = (fw_policy_df.iloc[:2], 1)
                                mock_protocol.return_value = ["Protocol warning"]
                                mock_ip.return_value = ["IP warning"]
                                
                                result = validator.perform_comprehensive_validation(fw_policy_df, fw_tag_df)
                                
                                assert isinstance(result, ValidationResult)
                                assert result.total_policies == 3
                                assert result.stateless_issues == 1
                                assert result.unused_tags == {"unused_tag"}
                                assert result.single_cidr_tags == {"10.0.0.0/8": "single_cidr_tag"}
                                assert result.duplicate_policies == 1
                                assert len(result.validation_warnings) == 2  # Protocol + IP warnings
                                assert result.issues_found == 5  # 1 + 1 + 1 + 2 = 5 total issues

    def test_perform_comprehensive_validation_no_issues(self):
        """Test comprehensive validation when no issues are found."""
        validator = PolicyValidator()
        
        fw_policy_df = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            "dst_ip": ["10.0.0.1"],
            "protocol": ["tcp"],
            "port": ["80"],
            "action": ["allow"]
        })
        
        fw_tag_df = pd.DataFrame({
            "firewall_tag": ["tag1"],
            "cidr_list": [{"cidr": "192.168.1.0/24"}]
        })
        
        # Mock all methods to return no issues
        with patch.object(validator, 'eval_stateless_alerts', return_value=pd.DataFrame()):
            with patch.object(validator, 'eval_unused_fw_tags', return_value=(fw_tag_df, set())):
                with patch.object(validator, 'eval_single_cidr_tag_match', return_value=(fw_policy_df, {})):
                    with patch.object(validator, 'identify_duplicate_policies', return_value=(fw_policy_df, 0)):
                        with patch.object(validator, 'validate_protocol_port_combinations', return_value=[]):
                            with patch.object(validator, 'validate_ip_addresses', return_value=[]):
                                
                                result = validator.perform_comprehensive_validation(fw_policy_df, fw_tag_df)
                                
                                assert result.total_policies == 1
                                assert result.issues_found == 0
                                assert result.stateless_issues == 0
                                assert len(result.unused_tags) == 0
                                assert len(result.single_cidr_tags) == 0
                                assert result.duplicate_policies == 0
                                assert len(result.validation_warnings) == 0
                                assert len(result.validation_errors) == 0
