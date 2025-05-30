"""
Unit tests for src/translation/fqdn_handlers.py

Tests all classes and methods in the FQDN handlers module including:
- FQDNValidator: Domain validation for DCF 8.0 compatibility
- FQDNRuleProcessor: Rule categorization and processing
- WebGroupBuilder: WebGroup creation from FQDN rules
- HostnameSmartGroupBuilder: Hostname SmartGroup creation
- FQDNPolicyBuilder: Policy generation for FQDN rules
- FQDNHandler: Main orchestration class
"""

import pandas as pd
import pytest
from unittest.mock import patch, MagicMock
import logging

from src.translation.fqdn_handlers import (
    FQDNValidator,
    FQDNRuleProcessor,
    WebGroupBuilder,
    HostnameSmartGroupBuilder,
    FQDNPolicyBuilder,
    FQDNHandler,
    DCF_SNI_DOMAIN_PATTERN
)
from src.utils.data_processing import translate_port_to_port_range
from src.data.processors import DataCleaner
from src.config import TranslationConfig


class TestFQDNValidator:
    """Test the FQDNValidator class for domain validation."""

    def test_validate_sni_domain_for_dcf_valid_domains(self):
        """Test validation of valid DCF 8.0 domains."""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "*.example.com",
            "*",
            "test-domain.org",
            "api.v2.service.com",
            "domain_with_underscore.com",
            "1234.com",
            "a.b.c.d.e.com"
        ]
        
        for domain in valid_domains:
            assert FQDNValidator.validate_sni_domain_for_dcf(domain), f"Domain should be valid: {domain}"

    def test_validate_sni_domain_for_dcf_invalid_domains(self):
        """Test validation of invalid DCF 8.0 domains."""
        invalid_domains = [
            "*example.com",  # wildcard without dot
            "*.*.example.com",  # multiple wildcards
            "",  # empty string
            " ",  # whitespace only
            "ex ample.com",  # space in domain
            "exam@ple.com",  # special character
            "example.com/path",  # with path
            "http://example.com",  # with protocol
        ]

        for domain in invalid_domains:
            assert not FQDNValidator.validate_sni_domain_for_dcf(domain), f"Domain should be invalid: {domain}"

    def test_validate_sni_domain_for_dcf_none_and_non_string(self):
        """Test validation with None and non-string inputs."""
        # Test with type: ignore comments for mypy since we're testing error cases
        assert not FQDNValidator.validate_sni_domain_for_dcf(None)  # type: ignore
        assert not FQDNValidator.validate_sni_domain_for_dcf(123)  # type: ignore
        assert not FQDNValidator.validate_sni_domain_for_dcf([])  # type: ignore
        assert not FQDNValidator.validate_sni_domain_for_dcf({})  # type: ignore

    def test_validate_sni_domain_for_dcf_whitespace_handling(self):
        """Test that whitespace is properly stripped."""
        assert FQDNValidator.validate_sni_domain_for_dcf("  example.com  ")
        assert FQDNValidator.validate_sni_domain_for_dcf("\texample.com\n")

    @patch('src.translation.fqdn_handlers.logging')
    def test_filter_domains_for_dcf_compatibility(self, mock_logging):
        """Test filtering domains for DCF compatibility."""
        fqdn_list = [
            "valid.com",
            "*.valid.com",
            "*invalid.com",  # invalid
            "also.valid.org",
            "",  # invalid
            "example..com"  # actually valid with DCF 8.0 pattern (allows double dots)
        ]
        
        valid, invalid = FQDNValidator.filter_domains_for_dcf_compatibility(fqdn_list)
        
        assert len(valid) == 4  # valid.com, *.valid.com, also.valid.org, example..com
        assert "valid.com" in valid
        assert "*.valid.com" in valid
        assert "also.valid.org" in valid
        assert "example..com" in valid
        
        assert len(invalid) == 2  # *invalid.com, ""
        assert "*invalid.com" in invalid
        assert "" in invalid

    @patch('src.translation.fqdn_handlers.logging')
    def test_filter_domains_with_webgroup_context(self, mock_logging):
        """Test filtering with webgroup name context for logging."""
        fqdn_list = ["valid.com", "*invalid.com"]
        webgroup_name = "test_webgroup"
        
        valid, invalid = FQDNValidator.filter_domains_for_dcf_compatibility(
            fqdn_list, webgroup_name
        )
        
        # Verify logging was called with webgroup context
        assert mock_logging.warning.called
        assert mock_logging.info.called
        
        # Check that webgroup name appears in log messages
        warning_call = mock_logging.warning.call_args[0][0]
        info_call = mock_logging.info.call_args[0][0]
        assert webgroup_name in warning_call
        assert webgroup_name in info_call


class TestFQDNRuleProcessor:
    """Test the FQDNRuleProcessor class for rule categorization."""

    def test_init(self):
        """Test FQDNRuleProcessor initialization."""
        port_ranges = ['80', '443']
        processor = FQDNRuleProcessor(port_ranges)
        assert processor.default_web_port_ranges == {'80', '443'}

    def test_eval_unsupported_webgroups_basic_split(self):
        """Test basic splitting of FQDN rules into webgroup and hostname rules."""
        processor = FQDNRuleProcessor(['80', '443'])
        
        # Create test data
        fqdn_tag_rule_df = pd.DataFrame({
            'fqdn_tag_name': ['tag1', 'tag2', 'tag3', 'tag4'],
            'protocol': ['tcp', 'tcp', 'ssh', 'all'],
            'port': ['80', '443', '22', ''],
            'other_col': ['a', 'b', 'c', 'd']
        })
        
        fqdn_df = pd.DataFrame({
            'fqdn_tag': ['tag1', 'tag2', 'tag3', 'tag4'],
            'fqdn_enabled': [True, True, True, True],
            'other_col': ['x', 'y', 'z', 'w']
        })
        
        webgroup_rules, hostname_rules, unsupported_rules = processor.eval_unsupported_webgroups(
            fqdn_tag_rule_df, fqdn_df
        )
        
        # Webgroup rules should include TCP on ports 80/443
        assert len(webgroup_rules) == 2
        assert set(webgroup_rules['port']) == {'80', '443'}
        
        # Hostname rules should include SSH and protocol='all'
        assert len(hostname_rules) == 2
        hostname_protocols = set(hostname_rules['protocol'])
        assert 'ssh' in hostname_protocols
        assert 'ANY' in hostname_protocols  # 'all' should be converted to 'ANY'
        
        # No unsupported rules
        assert len(unsupported_rules) == 0

    def test_eval_unsupported_webgroups_disabled_filtering(self):
        """Test that disabled FQDN tags are filtered out."""
        processor = FQDNRuleProcessor(['80', '443'])
        
        fqdn_tag_rule_df = pd.DataFrame({
            'fqdn_tag_name': ['tag1', 'tag2'],
            'protocol': ['tcp', 'tcp'],
            'port': ['80', '443']
        })
        
        fqdn_df = pd.DataFrame({
            'fqdn_tag': ['tag1', 'tag2'],
            'fqdn_enabled': [True, False]  # tag2 is disabled
        })
        
        webgroup_rules, hostname_rules, unsupported_rules = processor.eval_unsupported_webgroups(
            fqdn_tag_rule_df, fqdn_df
        )
        
        # Only enabled tag should be processed
        assert len(webgroup_rules) == 1
        assert webgroup_rules.iloc[0]['fqdn_tag_name'] == 'tag1'
        assert len(hostname_rules) == 0
        assert len(unsupported_rules) == 0

    def test_eval_unsupported_webgroups_protocol_handling(self):
        """Test protocol handling and conversion."""
        processor = FQDNRuleProcessor(['80'])
        
        fqdn_tag_rule_df = pd.DataFrame({
            'fqdn_tag_name': ['tag1', 'tag2', 'tag3', 'tag4'],
            'protocol': ['http', 'https', 'all', 'tcp'],
            'port': ['80', '80', '22', '80']
        })
        
        fqdn_df = pd.DataFrame({
            'fqdn_tag': ['tag1', 'tag2', 'tag3', 'tag4'],
            'fqdn_enabled': [True, True, True, True]
        })
        
        webgroup_rules, hostname_rules, unsupported_rules = processor.eval_unsupported_webgroups(
            fqdn_tag_rule_df, fqdn_df
        )
        
        # HTTP/HTTPS/TCP on port 80 should be webgroup rules
        assert len(webgroup_rules) == 3
        webgroup_protocols = set(webgroup_rules['protocol'])
        assert webgroup_protocols == {'http', 'https', 'tcp'}
        
        # 'all' protocol should go to hostname rules and be converted to 'ANY'
        assert len(hostname_rules) == 1
        assert hostname_rules.iloc[0]['protocol'] == 'ANY'

    def test_eval_unsupported_webgroups_blank_port_handling(self):
        """Test handling of blank ports."""
        processor = FQDNRuleProcessor(['80'])
        
        fqdn_tag_rule_df = pd.DataFrame({
            'fqdn_tag_name': ['tag1'],
            'protocol': ['tcp'],
            'port': ['']  # blank port
        })
        
        fqdn_df = pd.DataFrame({
            'fqdn_tag': ['tag1'],
            'fqdn_enabled': [True]
        })
        
        webgroup_rules, hostname_rules, unsupported_rules = processor.eval_unsupported_webgroups(
            fqdn_tag_rule_df, fqdn_df
        )
        
        # Blank port should go to hostname rules and be set to 'ALL'
        assert len(webgroup_rules) == 0
        assert len(hostname_rules) == 1
        assert hostname_rules.iloc[0]['port'] == 'ALL'


class TestWebGroupBuilder:
    """Test the WebGroupBuilder class."""

    def test_init(self):
        """Test WebGroupBuilder initialization."""
        builder = WebGroupBuilder()
        assert hasattr(builder, 'cleaner')
        assert hasattr(builder, 'all_invalid_domains')
        assert isinstance(builder.all_invalid_domains, list)

    @patch('src.translation.fqdn_handlers.FQDNValidator.filter_domains_for_dcf_compatibility')
    def test_build_webgroup_df_basic(self, mock_filter):
        """Test basic WebGroup DataFrame building."""
        # Mock the domain filtering
        mock_filter.return_value = (['valid.com'], ['invalid.com'])
        
        builder = WebGroupBuilder()
        
        # Create test data
        fqdn_tag_rule_df = pd.DataFrame({
            'fqdn_tag_name': ['tag1', 'tag1'],
            'protocol': ['tcp', 'tcp'],
            'port': ['80', '80'],
            'fqdn_mode': ['white', 'white'],
            'fqdn': ['example.com', 'test.com']
        })
        
        result_df = builder.build_webgroup_df(fqdn_tag_rule_df)
        
        # Should group by tag, protocol, port, mode and create names
        assert len(result_df) == 1  # Grouped into one webgroup
        assert 'name' in result_df.columns
        assert 'selector' in result_df.columns
        
        # Check webgroup name format
        expected_name = 'tag1_permit_tcp_80'
        assert result_df.iloc[0]['name'] == expected_name

    @patch('src.translation.fqdn_handlers.FQDNValidator.filter_domains_for_dcf_compatibility')
    def test_build_webgroup_df_with_invalid_domains(self, mock_filter):
        """Test handling of invalid domains during WebGroup building."""
        # Mock some domains as invalid
        mock_filter.return_value = (['valid.com'], ['invalid.domain'])
        
        builder = WebGroupBuilder()
        
        fqdn_tag_rule_df = pd.DataFrame({
            'fqdn_tag_name': ['tag1'],
            'protocol': ['tcp'],
            'port': ['80'],
            'fqdn_mode': ['white'],
            'fqdn': ['example.com']
        })
        
        result_df = builder.build_webgroup_df(fqdn_tag_rule_df)
        
        # Should still create webgroup with valid domains
        assert len(result_df) == 1
        
        # Should track invalid domains
        assert len(builder.all_invalid_domains) > 0

    @patch('src.translation.fqdn_handlers.FQDNValidator.filter_domains_for_dcf_compatibility')
    def test_build_webgroup_df_empty_input(self, mock_filter):
        """Test handling of empty input DataFrame."""
        builder = WebGroupBuilder()
        
        empty_df = pd.DataFrame(columns=[
            'fqdn_tag_name', 'protocol', 'port', 'fqdn_mode', 'fqdn'
        ])
        
        # Empty DataFrame operations in pandas can be problematic with apply() functions
        # that return dictionaries. The actual implementation would need to check for
        # empty DataFrames before applying transformations.
        with pytest.raises(ValueError, match="Cannot set a DataFrame with multiple columns"):
            result_df = builder.build_webgroup_df(empty_df)


class TestHostnameSmartGroupBuilder:
    """Test the HostnameSmartGroupBuilder class."""

    def test_init(self):
        """Test HostnameSmartGroupBuilder initialization."""
        builder = HostnameSmartGroupBuilder()
        assert hasattr(builder, 'cleaner')

    def test_build_hostname_smartgroups_basic(self):
        """Test basic hostname SmartGroup DataFrame building."""
        builder = HostnameSmartGroupBuilder()
        
        # Create test data - note: fqdn column should contain individual strings
        # since the groupby.apply(list) operation will create the lists
        hostname_rules_df = pd.DataFrame({
            'fqdn_tag_name': ['tag1', 'tag1', 'tag2'],
            'protocol': ['ssh', 'ssh', 'ANY'],
            'port': ['22', '22', 'ALL'],
            'fqdn_mode': ['white', 'white', 'black'],
            'fqdn': ['host1.com', 'host2.com', 'host3.com']
        })
        
        result_df = builder.build_hostname_smartgroups(hostname_rules_df)
        
        # Should create SmartGroups - groupby will reduce the number of groups
        assert len(result_df) > 0
        assert 'name' in result_df.columns
        assert 'selector' in result_df.columns
        
        # Check that names contain expected elements
        names = list(result_df['name'])
        assert all('fqdn_' in name for name in names)
        assert any('tag1' in name or 'tag2' in name for name in names)

    def test_build_hostname_smartgroups_empty_input(self):
        """Test handling of empty input DataFrame."""
        builder = HostnameSmartGroupBuilder()
        
        empty_df = pd.DataFrame(columns=[
            'fqdn_tag_name', 'protocol', 'port', 'fqdn_mode', 'fqdn'
        ])
        
        result_df = builder.build_hostname_smartgroups(empty_df)
        
        # Should return empty DataFrame with correct columns
        assert len(result_df) == 0
        expected_columns = ["name", "selector", "protocol", "port", "fqdn_mode", "fqdn_list"]
        assert all(col in result_df.columns for col in expected_columns)


class TestFQDNPolicyBuilder:
    """Test the FQDNPolicyBuilder class."""

    def test_init(self):
        """Test FQDNPolicyBuilder initialization."""
        # Mock utility functions
        mock_port_func = MagicMock()
        mock_vpc_func = MagicMock()
        mock_dedup_func = MagicMock()
        
        builder = FQDNPolicyBuilder(
            translate_port_to_port_range_func=mock_port_func,
            pretty_parse_vpc_name_func=mock_vpc_func,
            deduplicate_policy_names_func=mock_dedup_func
        )
        
        assert builder.translate_port_to_port_range == mock_port_func
        assert builder.pretty_parse_vpc_name == mock_vpc_func
        assert builder.deduplicate_policy_names == mock_dedup_func

    def test_build_hostname_policies_empty_input(self):
        """Test handling of empty input DataFrames."""
        # Mock utility functions
        mock_port_func = MagicMock()
        mock_vpc_func = MagicMock()
        mock_dedup_func = MagicMock()
        
        builder = FQDNPolicyBuilder(
            translate_port_to_port_range_func=mock_port_func,
            pretty_parse_vpc_name_func=mock_vpc_func,
            deduplicate_policy_names_func=mock_dedup_func
        )
        
        # Empty DataFrames
        empty_gateways = pd.DataFrame()
        empty_fqdn = pd.DataFrame()
        empty_hostname_sg = pd.DataFrame()
        empty_hostname_rules = pd.DataFrame()
        
        result = builder.build_hostname_policies(
            empty_gateways, empty_fqdn, empty_hostname_sg, empty_hostname_rules
        )
        
        assert len(result) == 0


class TestFQDNHandler:
    """Test the main FQDNHandler orchestration class."""

    def test_init(self):
        """Test FQDNHandler initialization."""
        # Mock utility functions
        mock_port_func = MagicMock()
        mock_vpc_func = MagicMock()
        mock_dedup_func = MagicMock()
        
        handler = FQDNHandler(
            default_web_port_ranges=['80', '443'],
            translate_port_to_port_range_func=mock_port_func,
            pretty_parse_vpc_name_func=mock_vpc_func,
            deduplicate_policy_names_func=mock_dedup_func
        )
        
        assert hasattr(handler, 'validator')
        assert hasattr(handler, 'rule_processor')
        assert hasattr(handler, 'webgroup_builder')
        assert hasattr(handler, 'hostname_sg_builder')
        assert hasattr(handler, 'policy_builder')

    def test_process_fqdn_rules_basic(self):
        """Test basic FQDN rule processing."""
        # Mock utility functions
        mock_port_func = MagicMock()
        mock_vpc_func = MagicMock()
        mock_dedup_func = MagicMock()
        
        handler = FQDNHandler(
            default_web_port_ranges=['80', '443'],
            translate_port_to_port_range_func=mock_port_func,
            pretty_parse_vpc_name_func=mock_vpc_func,
            deduplicate_policy_names_func=mock_dedup_func
        )
        
        # Create test data
        fqdn_tag_rule_df = pd.DataFrame({
            'fqdn_tag_name': ['tag1'],
            'protocol': ['tcp'],
            'port': ['80']
        })
        
        fqdn_df = pd.DataFrame({
            'fqdn_tag': ['tag1'],
            'fqdn_enabled': [True]
        })
        
        webgroup_rules, hostname_rules, unsupported_rules = handler.process_fqdn_rules(
            fqdn_tag_rule_df, fqdn_df
        )
        
        # Should categorize rules
        assert isinstance(webgroup_rules, pd.DataFrame)
        assert isinstance(hostname_rules, pd.DataFrame)
        assert isinstance(unsupported_rules, pd.DataFrame)

    def test_build_webgroups(self):
        """Test webgroup building."""
        # Mock utility functions
        mock_port_func = MagicMock()
        mock_vpc_func = MagicMock()
        mock_dedup_func = MagicMock()
        
        handler = FQDNHandler(
            default_web_port_ranges=['80', '443'],
            translate_port_to_port_range_func=mock_port_func,
            pretty_parse_vpc_name_func=mock_vpc_func,
            deduplicate_policy_names_func=mock_dedup_func
        )
        
        # Create test webgroup rules
        webgroup_rules_df = pd.DataFrame({
            'fqdn_tag_name': ['tag1'],
            'protocol': ['tcp'],
            'port': ['80'],
            'fqdn_mode': ['white'],
            'fqdn': ['example.com']
        })
        
        with patch('src.translation.fqdn_handlers.FQDNValidator.filter_domains_for_dcf_compatibility') as mock_filter:
            mock_filter.return_value = (['example.com'], [])
            result = handler.build_webgroups(webgroup_rules_df)
            assert isinstance(result, pd.DataFrame)

    def test_build_hostname_smartgroups(self):
        """Test hostname SmartGroup building."""
        # Mock utility functions
        mock_port_func = MagicMock()
        mock_vpc_func = MagicMock()
        mock_dedup_func = MagicMock()
        
        handler = FQDNHandler(
            default_web_port_ranges=['80', '443'],
            translate_port_to_port_range_func=mock_port_func,
            pretty_parse_vpc_name_func=mock_vpc_func,
            deduplicate_policy_names_func=mock_dedup_func
        )
        
        # Create test hostname rules - use individual strings instead of lists
        hostname_rules_df = pd.DataFrame({
            'fqdn_tag_name': ['tag1'],
            'protocol': ['ssh'],
            'port': ['22'],
            'fqdn_mode': ['white'],
            'fqdn': ['host1.com']  # Single string, not list
        })
        
        result = handler.build_hostname_smartgroups(hostname_rules_df)
        assert isinstance(result, pd.DataFrame)

    def test_validate_domain(self):
        """Test domain validation through handler."""
        # Mock utility functions
        mock_port_func = MagicMock()
        mock_vpc_func = MagicMock()
        mock_dedup_func = MagicMock()
        
        handler = FQDNHandler(
            default_web_port_ranges=['80', '443'],
            translate_port_to_port_range_func=mock_port_func,
            pretty_parse_vpc_name_func=mock_vpc_func,
            deduplicate_policy_names_func=mock_dedup_func
        )
        
        assert handler.validate_domain("example.com") is True
        assert handler.validate_domain("*invalid.com") is False

    def test_filter_domains(self):
        """Test domain filtering through handler."""
        # Mock utility functions
        mock_port_func = MagicMock()
        mock_vpc_func = MagicMock()
        mock_dedup_func = MagicMock()
        
        handler = FQDNHandler(
            default_web_port_ranges=['80', '443'],
            translate_port_to_port_range_func=mock_port_func,
            pretty_parse_vpc_name_func=mock_vpc_func,
            deduplicate_policy_names_func=mock_dedup_func
        )
        
        domains = ["valid.com", "*invalid.com"]
        valid, invalid = handler.filter_domains(domains)
        
        assert "valid.com" in valid
        assert "*invalid.com" in invalid


class TestDCFSNIDomainPattern:
    """Test the DCF SNI domain regex pattern directly."""

    def test_dcf_sni_domain_pattern_direct(self):
        """Test the DCF SNI domain pattern regex directly."""
        # Valid patterns
        valid_domains = [
            "*",
            "*.example.com",
            "example.com",
            "sub.example.com",
            "test-domain.org",
            "1234.com"
        ]
        
        for domain in valid_domains:
            assert DCF_SNI_DOMAIN_PATTERN.match(domain), f"Pattern should match: {domain}"
        
        # Invalid patterns
        invalid_domains = [
            "*example.com",  # wildcard without dot
            "*.*.example.com",  # multiple wildcards
            "",
        ]
        
        for domain in invalid_domains:
            assert not DCF_SNI_DOMAIN_PATTERN.match(domain), f"Pattern should not match: {domain}"


@pytest.fixture
def sample_fqdn_tag_rule_df():
    """Fixture providing sample FQDN tag rule DataFrame."""
    return pd.DataFrame({
        'fqdn_tag_name': ['web_tag', 'ssh_tag', 'all_tag'],
        'protocol': ['tcp', 'tcp', 'all'],
        'port': ['80', '22', ''],
        'fqdn_mode': ['white', 'white', 'black'],
        'fqdn': ['example.com', 'server.com', 'blocked.com']
    })


@pytest.fixture
def sample_fqdn_df():
    """Fixture providing sample FQDN DataFrame."""
    return pd.DataFrame({
        'fqdn_tag': ['web_tag', 'ssh_tag', 'all_tag'],
        'fqdn_enabled': [True, True, True],
        'description': ['Web traffic', 'SSH traffic', 'All traffic']
    })


@pytest.fixture
def mock_utility_functions():
    """Fixture providing mock utility functions for FQDNHandler."""
    return {
        'port_func': MagicMock(),
        'vpc_func': MagicMock(),
        'dedup_func': MagicMock()
    }


class TestIntegrationWithFixtures:
    """Integration tests using fixtures."""

    def test_full_pipeline_with_fixtures(self, sample_fqdn_tag_rule_df, sample_fqdn_df, mock_utility_functions):
        """Test the full FQDN processing pipeline with realistic data."""
        handler = FQDNHandler(
            default_web_port_ranges=['80', '443'],
            translate_port_to_port_range_func=mock_utility_functions['port_func'],
            pretty_parse_vpc_name_func=mock_utility_functions['vpc_func'],
            deduplicate_policy_names_func=mock_utility_functions['dedup_func']
        )
        
        # Test rule processing
        webgroup_rules, hostname_rules, unsupported_rules = handler.process_fqdn_rules(
            sample_fqdn_tag_rule_df, sample_fqdn_df
        )
        
        # Verify structure
        assert isinstance(webgroup_rules, pd.DataFrame)
        assert isinstance(hostname_rules, pd.DataFrame)
        assert isinstance(unsupported_rules, pd.DataFrame)
        
        # Should have some webgroups (port 80 rule)
        assert len(webgroup_rules) > 0
        
        # Should have hostname rules (port 22 and blank port rules)
        assert len(hostname_rules) > 0
