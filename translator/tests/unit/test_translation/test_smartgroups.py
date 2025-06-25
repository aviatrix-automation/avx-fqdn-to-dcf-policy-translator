"""
Comprehensive unit tests for src.translation.smartgroups module.

Tests all SmartGroup building functionality including firewall tags, CIDRs, VPCs, and hostnames.
"""

import pandas as pd
import pytest
from unittest.mock import MagicMock, patch

from src.translation.smartgroups import SmartGroupBuilder
from src.config import TranslationConfig


class TestSmartGroupBuilder:
    """Test the SmartGroupBuilder class."""

    def test_init(self):
        """Test SmartGroupBuilder initialization."""
        config = TranslationConfig()
        builder = SmartGroupBuilder(config)
        
        assert builder.config is config
        assert builder.cleaner is not None
        assert builder.logger is not None

    def test_translate_fw_tag_to_sg_selector_dict_input(self):
        """Test translation with dictionary input."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        tag_cidrs = {"cidr": "10.0.0.0/24"}
        result = builder.translate_fw_tag_to_sg_selector(tag_cidrs)
        
        expected = {"match_expressions": {"cidr": "10.0.0.0/24"}}
        assert result == expected

    def test_translate_fw_tag_to_sg_selector_list_input(self):
        """Test translation with list input."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        tag_cidrs = [
            {"cidr": "10.0.0.0/24"},
            {"cidr": "192.168.1.0/24"}
        ]
        result = builder.translate_fw_tag_to_sg_selector(tag_cidrs)
        
        expected = {
            "match_expressions": [
                {"cidr": "10.0.0.0/24"},
                {"cidr": "192.168.1.0/24"}
            ]
        }
        assert result == expected

    def test_translate_fw_tag_to_sg_selector_none_input(self):
        """Test translation with None input."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        result = builder.translate_fw_tag_to_sg_selector(None)
        
        expected = {"match_expressions": None}
        assert result == expected

    def test_translate_fw_tag_to_sg_selector_invalid_input(self):
        """Test translation with invalid input."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        result = builder.translate_fw_tag_to_sg_selector("invalid")
        
        expected = {"match_expressions": None}
        assert result == expected


class TestFirewallTagSmartGroups:
    """Test firewall tag SmartGroup building."""

    def test_build_firewall_tag_smartgroups_basic(self):
        """Test basic firewall tag SmartGroup building."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        fw_tag_df = pd.DataFrame({
            'firewall_tag': ['web-servers', 'db-servers'],
            'cidr_list': [
                [{"cidr": "10.0.1.0/24"}, {"cidr": "10.0.2.0/24"}],
                [{"cidr": "10.0.3.0/24"}]
            ]
        })
        
        result_df = builder.build_firewall_tag_smartgroups(fw_tag_df)
        
        assert len(result_df) == 2
        assert list(result_df.columns) == ['name', 'selector']
        assert result_df.iloc[0]['name'] == 'web-servers'
        assert result_df.iloc[1]['name'] == 'db-servers'
        
        # Check selector structure
        web_selector = result_df.iloc[0]['selector']
        assert 'match_expressions' in web_selector
        assert len(web_selector['match_expressions']) == 2
        assert web_selector['match_expressions'][0]['cidr'] == "10.0.1.0/24"

    def test_build_firewall_tag_smartgroups_empty_input(self):
        """Test firewall tag SmartGroup building with empty input."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        fw_tag_df = pd.DataFrame()
        result_df = builder.build_firewall_tag_smartgroups(fw_tag_df)
        
        assert len(result_df) == 0
        assert list(result_df.columns) == ['name', 'selector']

    def test_build_firewall_tag_smartgroups_single_cidr(self):
        """Test firewall tag SmartGroup building with single CIDR."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        fw_tag_df = pd.DataFrame({
            'firewall_tag': ['single-server'],
            'cidr_list': [{"cidr": "10.0.1.100/32"}]
        })
        
        result_df = builder.build_firewall_tag_smartgroups(fw_tag_df)
        
        assert len(result_df) == 1
        assert result_df.iloc[0]['name'] == 'single-server'
        
        # Check single CIDR selector structure
        selector = result_df.iloc[0]['selector']
        assert selector['match_expressions']['cidr'] == "10.0.1.100/32"


class TestCIDRSmartGroups:
    """Test CIDR-based SmartGroup building."""

    def test_build_cidr_smartgroups_basic(self):
        """Test basic CIDR SmartGroup building."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        # Mock the _is_valid_cidr method
        with patch.object(builder, '_is_valid_cidr') as mock_valid_cidr:
            mock_valid_cidr.side_effect = lambda x: x in ['10.0.0.0/24', '192.168.1.0/24']
            
            fw_policy_df = pd.DataFrame({
                'src_ip': ['10.0.0.0/24', 'web-servers', '192.168.1.0/24'],
                'dst_ip': ['any', '10.0.0.0/24', 'db-servers']
            })
            
            fw_tag_df = pd.DataFrame({
                'firewall_tag': ['web-servers', 'db-servers']
            })
            
            result_df = builder.build_cidr_smartgroups(fw_policy_df, fw_tag_df)
            
            assert len(result_df) == 2
            assert list(result_df.columns) == ['selector', 'name']
            
            # Check that CIDR names are created properly
            names = set(result_df['name'])
            assert 'cidr_10.0.0.0/24' in names
            assert 'cidr_192.168.1.0/24' in names
            
            # Check selector structure
            for _, row in result_df.iterrows():
                selector = row['selector']
                assert 'match_expressions' in selector
                assert 'cidr' in selector['match_expressions']

    def test_build_cidr_smartgroups_empty_policies(self):
        """Test CIDR SmartGroup building with empty policies."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        fw_policy_df = pd.DataFrame()
        fw_tag_df = pd.DataFrame()
        
        result_df = builder.build_cidr_smartgroups(fw_policy_df, fw_tag_df)
        
        assert len(result_df) == 0
        assert list(result_df.columns) == ['name', 'selector']

    def test_build_cidr_smartgroups_no_valid_cidrs(self):
        """Test CIDR SmartGroup building with no valid CIDRs."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        # Mock _is_valid_cidr to return False for all
        with patch.object(builder, '_is_valid_cidr', return_value=False):
            fw_policy_df = pd.DataFrame({
                'src_ip': ['web-servers', 'any'],
                'dst_ip': ['db-servers', 'internet']
            })
            
            fw_tag_df = pd.DataFrame()
            
            result_df = builder.build_cidr_smartgroups(fw_policy_df, fw_tag_df)
            
            assert len(result_df) == 0

    def test_build_cidr_smartgroups_excludes_existing_tags(self):
        """Test that existing firewall tags are excluded from CIDR SmartGroups."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        with patch.object(builder, '_is_valid_cidr') as mock_valid_cidr:
            mock_valid_cidr.side_effect = lambda x: x == '10.0.0.0/24'
            
            fw_policy_df = pd.DataFrame({
                'src_ip': ['10.0.0.0/24', 'existing-tag'],
                'dst_ip': ['any', '10.0.0.0/24']
            })
            
            fw_tag_df = pd.DataFrame({
                'firewall_tag': ['existing-tag']
            })
            
            result_df = builder.build_cidr_smartgroups(fw_policy_df, fw_tag_df)
            
            # Should only create SmartGroup for the CIDR, not the existing tag
            assert len(result_df) == 1
            assert result_df.iloc[0]['name'] == 'cidr_10.0.0.0/24'


class TestVPCSmartGroups:
    """Test VPC-based SmartGroup building."""

    def test_build_vpc_smartgroups_basic(self):
        """Test basic VPC SmartGroup building."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        # Mock the cleaner method
        with patch.object(builder.cleaner, 'pretty_parse_vpc_name') as mock_parse:
            mock_parse.return_value = pd.Series(['vpc-123-cleaned', 'vpc-456-cleaned'])
            
            gateways_df = pd.DataFrame({
                'vpc_id': ['vpc-123', 'vpc-456', 'vpc-123'],  # vpc-123 appears twice
                'vpc_region': ['us-east-1', 'us-west-2', 'us-east-1'],
                'account_name': ['account1', 'account2', 'account1'],
                'other_field': ['data1', 'data2', 'data3']
            })
            
            result_df = builder.build_vpc_smartgroups(gateways_df)
            
            # Should deduplicate to 2 unique VPCs
            assert len(result_df) == 2
            assert list(result_df.columns) == ['name', 'selector']
            
            # Check names are cleaned
            names = list(result_df['name'])
            assert 'vpc-123-cleaned' in names
            assert 'vpc-456-cleaned' in names
            
            # Check selector structure
            for _, row in result_df.iterrows():
                selector = row['selector']
                assert 'match_expressions' in selector
                match_exp = selector['match_expressions']
                assert 'name' in match_exp
                assert 'region' in match_exp
                assert 'account_name' in match_exp
                assert match_exp['type'] == 'vpc'

    def test_build_vpc_smartgroups_empty_input(self):
        """Test VPC SmartGroup building with empty input."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        gateways_df = pd.DataFrame()
        result_df = builder.build_vpc_smartgroups(gateways_df)
        
        assert len(result_df) == 0
        assert list(result_df.columns) == ['name', 'selector']

    def test_build_vpc_smartgroups_single_vpc(self):
        """Test VPC SmartGroup building with single VPC."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        with patch.object(builder.cleaner, 'pretty_parse_vpc_name') as mock_parse:
            mock_parse.return_value = pd.Series(['vpc-single-cleaned'])
            
            gateways_df = pd.DataFrame({
                'vpc_id': ['vpc-single'],
                'vpc_region': ['us-east-1'],
                'account_name': ['test-account']
            })
            
            result_df = builder.build_vpc_smartgroups(gateways_df)
            
            assert len(result_df) == 1
            assert result_df.iloc[0]['name'] == 'vpc-single-cleaned'
            
            selector = result_df.iloc[0]['selector']
            match_exp = selector['match_expressions']
            assert match_exp['name'] == 'vpc-single-cleaned'
            assert match_exp['region'] == 'us-east-1'
            assert match_exp['account_name'] == 'test-account'
            assert match_exp['type'] == 'vpc'


class TestHostnameSmartGroups:
    """Test hostname-based SmartGroup building."""

    def test_build_hostname_smartgroups_basic(self):
        """Test basic hostname SmartGroup building."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        hostname_rules_df = pd.DataFrame({
            'fqdn_tag_name': ['web-tag', 'api-tag', 'web-tag'],
            'fqdn': ['example.com', 'api.service.com', 'test.example.com'],
            'protocol': ['tcp', 'tcp', 'tcp'],
            'port': ['443', '8080', '443'],
            'fqdn_mode': ['white', 'white', 'white']
        })
        
        result_df = builder.build_hostname_smartgroups(hostname_rules_df)
        
        # Should group by tag, protocol, port, and mode
        assert len(result_df) >= 1  # At least one group
        assert list(result_df.columns) == ['name', 'selector', 'protocol', 'port', 'fqdn_mode', 'fqdn_list']
        
        # Check that FQDNs are grouped properly
        for _, row in result_df.iterrows():
            assert isinstance(row['fqdn_list'], list)
            assert len(row['fqdn_list']) >= 1
            
            # Check selector structure
            selector = row['selector']
            assert 'match_expressions' in selector
            match_expressions = selector['match_expressions']
            assert isinstance(match_expressions, list)
            
            # Each match expression should have an fqdn field
            for match_exp in match_expressions:
                assert 'fqdn' in match_exp

    def test_build_hostname_smartgroups_empty_input(self):
        """Test hostname SmartGroup building with empty input."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        hostname_rules_df = pd.DataFrame()
        result_df = builder.build_hostname_smartgroups(hostname_rules_df)
        
        assert len(result_df) == 0
        assert list(result_df.columns) == ['name', 'selector', 'protocol', 'port', 'fqdn_mode', 'fqdn_list']

    def test_build_hostname_smartgroups_grouping_logic(self):
        """Test that hostname SmartGroups are grouped correctly."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        hostname_rules_df = pd.DataFrame({
            'fqdn_tag_name': ['web-tag', 'web-tag', 'api-tag'],
            'fqdn': ['example.com', 'test.com', 'api.com'],
            'protocol': ['tcp', 'tcp', 'tcp'],
            'port': ['443', '443', '8080'],  # First two same port, third different
            'fqdn_mode': ['white', 'white', 'white']
        })
        
        result_df = builder.build_hostname_smartgroups(hostname_rules_df)
        
        # Should create 2 groups: one for web-tag:443, one for api-tag:8080
        assert len(result_df) == 2
        
        # Find the web-tag group (port 443)
        web_group = result_df[result_df['port'] == '443'].iloc[0]
        assert web_group['fqdn_mode'] == 'white'
        assert len(web_group['fqdn_list']) == 2
        assert 'example.com' in web_group['fqdn_list']
        assert 'test.com' in web_group['fqdn_list']
        assert 'web-tag' in web_group['name']  # Name should contain fqdn_tag_name
        
        # Find the api-tag group (port 8080)
        api_group = result_df[result_df['port'] == '8080'].iloc[0]
        assert api_group['fqdn_mode'] == 'white'
        assert len(api_group['fqdn_list']) == 1
        assert 'api.com' in api_group['fqdn_list']
        assert 'api-tag' in api_group['name']  # Name should contain fqdn_tag_name


class TestHelperMethods:
    """Test helper methods in SmartGroupBuilder."""

    def test_is_valid_cidr_valid_cases(self):
        """Test _is_valid_cidr with valid IP addresses and CIDRs."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        valid_cases = [
            '10.0.0.0/24',
            '192.168.1.0/24',
            '172.16.0.0/16',
            '10.0.0.1/32',
            '0.0.0.0/0',
            '127.0.0.1',
            '192.168.1.100'
        ]
        
        for case in valid_cases:
            assert builder._is_valid_cidr(case), f"Should be valid: {case}"

    def test_is_valid_cidr_invalid_cases(self):
        """Test _is_valid_cidr with invalid inputs."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        invalid_cases = [
            'any',
            'internet', 
            'web-servers',
            'not-an-ip',
            '300.0.0.1',
            '10.0.0.0/40',
            '',
            None,
            4294967296,  # Too large for IPv4
            []
        ]
        
        for case in invalid_cases:
            assert not builder._is_valid_cidr(case), f"Should be invalid: {case}"

    def test_is_valid_cidr_edge_cases(self):
        """Test _is_valid_cidr with edge cases."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        # Test edge cases that might be tricky
        edge_cases = [
            ('10.0.0.0/0', True),   # Valid CIDR
            ('255.255.255.255', True),  # Valid IP
            ('0.0.0.0', True),  # Valid IP
            ('10.0.0.0/33', False),  # Invalid subnet mask
            ('256.0.0.1', False),  # Invalid IP range
            ('10.0.0', False),  # Incomplete IP
            ('10.0.0.0.0', False),  # Too many octets
        ]
        
        for case, expected in edge_cases:
            result = builder._is_valid_cidr(case)
            assert result == expected, f"Expected {expected} for {case}, got {result}"


class TestSmartGroupBuilderIntegration:
    """Integration tests for SmartGroupBuilder."""

    def test_all_smartgroup_types_together(self):
        """Test that all SmartGroup building methods work together."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        # Test data for different SmartGroup types
        fw_tag_df = pd.DataFrame({
            'firewall_tag': ['web-servers'],
            'cidr_list': [[{"cidr": "10.0.1.0/24"}]]
        })
        
        fw_policy_df = pd.DataFrame({
            'src_ip': ['192.168.1.0/24', 'web-servers'],
            'dst_ip': ['any', '10.0.2.0/24']
        })
        
        gateways_df = pd.DataFrame({
            'vpc_id': ['vpc-123'],
            'vpc_region': ['us-east-1'],
            'account_name': ['test-account']
        })
        
        hostname_rules_df = pd.DataFrame({
            'fqdn_tag_name': ['web-fqdn'],
            'fqdn': ['example.com'],
            'protocol': ['tcp'],
            'port': ['443'],
            'fqdn_mode': ['white']
        })
        
        # Mock dependencies
        with patch.object(builder, '_is_valid_cidr') as mock_valid_cidr, \
             patch.object(builder.cleaner, 'pretty_parse_vpc_name') as mock_parse:
            
            mock_valid_cidr.side_effect = lambda x: x in ['192.168.1.0/24', '10.0.2.0/24']
            mock_parse.return_value = pd.Series(['vpc-123-clean'])
            
            # Build all SmartGroup types
            tag_sgs = builder.build_firewall_tag_smartgroups(fw_tag_df)
            cidr_sgs = builder.build_cidr_smartgroups(fw_policy_df, fw_tag_df)
            vpc_sgs = builder.build_vpc_smartgroups(gateways_df)
            hostname_sgs = builder.build_hostname_smartgroups(hostname_rules_df)
            
            # Verify each type was created
            assert len(tag_sgs) == 1
            assert len(cidr_sgs) == 2  # Two valid CIDRs not in tags
            assert len(vpc_sgs) == 1
            assert len(hostname_sgs) == 1
            
            # All should have consistent structure
            for df in [tag_sgs, cidr_sgs, vpc_sgs]:
                assert 'name' in df.columns
                assert 'selector' in df.columns
            
            # Hostname SmartGroups have additional columns
            assert 'protocol' in hostname_sgs.columns
            assert 'port' in hostname_sgs.columns
            assert 'fqdn_mode' in hostname_sgs.columns
            assert 'fqdn_list' in hostname_sgs.columns

    def test_error_handling_and_logging(self):
        """Test error handling and logging in SmartGroup building."""
        builder = SmartGroupBuilder(TranslationConfig())
        
        # Test with malformed data
        malformed_fw_tag_df = pd.DataFrame({
            'firewall_tag': ['test'],
            'cidr_list': [None]  # None instead of list
        })
        
        # Should not crash and should handle gracefully
        result_df = builder.build_firewall_tag_smartgroups(malformed_fw_tag_df)
        assert len(result_df) == 1  # Should still create entry
        
        # Check that selector was created (even if None)
        assert 'selector' in result_df.columns
        assert result_df.iloc[0]['selector']['match_expressions'] is None

    def test_data_cleaning_integration(self):
        """Test that data cleaning is properly integrated."""
        config = TranslationConfig()
        builder = SmartGroupBuilder(config)
        
        # Verify that the cleaner is properly initialized and used
        assert builder.cleaner.config is config
        
        # Test that cleaner methods are available (they should be mocked in real tests)
        assert hasattr(builder.cleaner, 'pretty_parse_vpc_name')
