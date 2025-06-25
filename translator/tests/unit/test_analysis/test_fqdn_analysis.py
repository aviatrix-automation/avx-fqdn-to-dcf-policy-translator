"""
Unit tests for FQDN analysis module.

Tests the FQDNAnalysisResult dataclass, FQDNCategorizer, DomainCompatibilityAnalyzer,
and FQDNAnalyzer classes for analyzing FQDN rules and domain compatibility.
"""

import pytest
import pandas as pd
from unittest.mock import Mock, patch, MagicMock
from collections import defaultdict

from src.analysis.fqdn_analysis import (
    FQDNAnalysisResult,
    FQDNCategorizer,
    DomainCompatibilityAnalyzer,
    FQDNAnalyzer
)


class TestFQDNAnalysisResult:
    """Test the FQDNAnalysisResult dataclass."""

    def test_fqdn_analysis_result_creation(self):
        """Test creating FQDNAnalysisResult with all fields."""
        result = FQDNAnalysisResult(
            total_rules=100,
            enabled_rules=80,
            disabled_rules=20,
            webgroup_rules=30,
            hostname_rules=50,
            unsupported_rules=0,
            unique_domains=45,
            dcf_compatible_domains=42,
            dcf_incompatible_domains=3,
            protocol_breakdown={"tcp": 70, "udp": 10},
            port_breakdown={"443": 30, "80": 20},
            mode_breakdown={"white": 60, "black": 20},
            gateway_breakdown={"gw1": 40, "gw2": 40}
        )

        assert result.total_rules == 100
        assert result.enabled_rules == 80
        assert result.disabled_rules == 20
        assert result.webgroup_rules == 30
        assert result.hostname_rules == 50
        assert result.unsupported_rules == 0
        assert result.unique_domains == 45
        assert result.dcf_compatible_domains == 42
        assert result.dcf_incompatible_domains == 3
        assert result.protocol_breakdown == {"tcp": 70, "udp": 10}
        assert result.port_breakdown == {"443": 30, "80": 20}
        assert result.mode_breakdown == {"white": 60, "black": 20}
        assert result.gateway_breakdown == {"gw1": 40, "gw2": 40}


class TestFQDNCategorizer:
    """Test the FQDNCategorizer class."""

    def test_init_with_default_ports(self):
        """Test initialization with default web ports."""
        categorizer = FQDNCategorizer()
        assert categorizer.default_web_ports == {"80", "443"}

    def test_init_with_custom_ports(self):
        """Test initialization with custom web ports."""
        custom_ports = {"80", "443", "8080", "8443"}
        categorizer = FQDNCategorizer(default_web_ports=custom_ports)
        assert categorizer.default_web_ports == custom_ports

    def test_categorize_by_protocol_port_empty_dataframe(self):
        """Test categorization with empty FQDN rules DataFrame."""
        categorizer = FQDNCategorizer()
        empty_df = pd.DataFrame()
        
        result = categorizer.categorize_by_protocol_port(empty_df)
        
        assert "webgroup_rules" in result
        assert "hostname_rules" in result
        assert "unsupported_rules" in result
        assert result["webgroup_rules"].empty
        assert result["hostname_rules"].empty
        assert result["unsupported_rules"].empty

    def test_categorize_by_protocol_port_basic(self):
        """Test basic protocol/port categorization."""
        categorizer = FQDNCategorizer()
        
        # Create test data
        fqdn_rules_df = pd.DataFrame({
            "fqdn_tag_name": ["web_tag", "ssh_tag", "custom_tag"],
            "fqdn": ["example.com", "ssh.example.com", "custom.example.com"],
            "protocol": ["tcp", "tcp", "udp"],
            "port": ["443", "22", "53"]
        })
        
        result = categorizer.categorize_by_protocol_port(fqdn_rules_df)
        
        # WebGroup rules should include TCP on port 443
        assert len(result["webgroup_rules"]) == 1
        assert result["webgroup_rules"].iloc[0]["fqdn"] == "example.com"
        
        # Hostname rules should include non-webgroup rules
        assert len(result["hostname_rules"]) == 2
        assert "ssh.example.com" in result["hostname_rules"]["fqdn"].values
        assert "custom.example.com" in result["hostname_rules"]["fqdn"].values

    def test_categorize_by_protocol_port_with_fqdn_filtering(self):
        """Test categorization with FQDN filtering by enabled status."""
        categorizer = FQDNCategorizer()
        
        # Create test data
        fqdn_rules_df = pd.DataFrame({
            "fqdn_tag_name": ["enabled_tag", "disabled_tag", "another_enabled"],
            "fqdn": ["enabled.com", "disabled.com", "another.com"],
            "protocol": ["tcp", "tcp", "tcp"],
            "port": ["443", "443", "80"]
        })
        
        fqdn_df = pd.DataFrame({
            "fqdn_tag": ["enabled_tag", "disabled_tag", "another_enabled"],
            "fqdn_enabled": [True, False, True]
        })
        
        result = categorizer.categorize_by_protocol_port(fqdn_rules_df, fqdn_df)
        
        # Should only include enabled rules
        assert len(result["webgroup_rules"]) == 2
        enabled_domains = result["webgroup_rules"]["fqdn"].tolist()
        assert "enabled.com" in enabled_domains
        assert "another.com" in enabled_domains
        assert "disabled.com" not in enabled_domains

    def test_categorize_by_protocol_port_protocol_conversion(self):
        """Test protocol conversion for hostname rules."""
        categorizer = FQDNCategorizer()
        
        fqdn_rules_df = pd.DataFrame({
            "fqdn_tag_name": ["all_tag", "tcp_tag"],
            "fqdn": ["all.example.com", "tcp.example.com"],
            "protocol": ["all", "tcp"],
            "port": ["", "22"]
        })
        
        result = categorizer.categorize_by_protocol_port(fqdn_rules_df)
        
        hostname_rules = result["hostname_rules"]
        
        # Check protocol conversion
        all_rule = hostname_rules[hostname_rules["fqdn"] == "all.example.com"]
        assert all_rule.iloc[0]["protocol"] == "ANY"
        
        # Check port conversion for blank ports
        assert all_rule.iloc[0]["port"] == "ALL"

    def test_categorize_by_mode(self):
        """Test categorization by FQDN mode."""
        categorizer = FQDNCategorizer()
        
        fqdn_rules_df = pd.DataFrame({
            "fqdn_tag_name": ["white_tag", "black_tag", "white_tag2"],
            "fqdn": ["white1.com", "black1.com", "white2.com"],
            "fqdn_mode": ["white", "black", "white"]
        })
        
        result = categorizer.categorize_by_mode(fqdn_rules_df)
        
        assert "white_rules" in result
        assert "black_rules" in result
        assert len(result["white_rules"]) == 2
        assert len(result["black_rules"]) == 1
        
        white_domains = result["white_rules"]["fqdn"].tolist()
        assert "white1.com" in white_domains
        assert "white2.com" in white_domains
        
        black_domains = result["black_rules"]["fqdn"].tolist()
        assert "black1.com" in black_domains

    def test_categorize_by_gateway_with_valid_data(self):
        """Test categorization by gateway with valid gateway filter data."""
        categorizer = FQDNCategorizer()
        
        fqdn_rules_df = pd.DataFrame({
            "fqdn_tag_name": ["gw1_tag", "gw2_tag"],
            "fqdn": ["gw1.example.com", "gw2.example.com"],
            "gw_filter_tag_list": [
                {"gw_name": "gateway1"},
                {"gw_name": "gateway2"}
            ]
        })
        
        result = categorizer.categorize_by_gateway(fqdn_rules_df)
        
        assert "gateway1" in result
        assert "gateway2" in result
        assert len(result["gateway1"]) == 1
        assert len(result["gateway2"]) == 1
        assert result["gateway1"].iloc[0]["fqdn"] == "gw1.example.com"
        assert result["gateway2"].iloc[0]["fqdn"] == "gw2.example.com"

    def test_categorize_by_gateway_no_gw_filter_column(self):
        """Test categorization by gateway when no gw_filter_tag_list column exists."""
        categorizer = FQDNCategorizer()
        
        fqdn_rules_df = pd.DataFrame({
            "fqdn_tag_name": ["tag1", "tag2"],
            "fqdn": ["example1.com", "example2.com"]
        })
        
        result = categorizer.categorize_by_gateway(fqdn_rules_df)
        
        # Should return empty dictionary when no gateway info
        assert result == {}


class TestDomainCompatibilityAnalyzer:
    """Test the DomainCompatibilityAnalyzer class."""

    @patch('src.analysis.fqdn_analysis.DCF_SNI_DOMAIN_PATTERN')
    def test_init(self, mock_pattern):
        """Test initialization of DomainCompatibilityAnalyzer."""
        mock_pattern.return_value = r'^[\w\.-]+$'
        analyzer = DomainCompatibilityAnalyzer()
        assert analyzer.sni_pattern == mock_pattern

    def test_analyze_domain_compatibility_valid_domains(self):
        """Test domain compatibility analysis with valid domains."""
        analyzer = DomainCompatibilityAnalyzer()
        domains = ["example.com", "sub.example.com", "*.wildcard.com"]
        
        with patch('re.match') as mock_match:
            # Mock valid domains
            mock_match.return_value = True
            
            result = analyzer.analyze_domain_compatibility(domains)
            
            assert result["total_domains"] == 3
            assert result["valid_count"] == 3
            assert result["invalid_count"] == 0
            assert result["compatibility_rate"] == 1.0
            assert result["valid_domains"] == domains
            assert result["invalid_domains"] == []

    def test_analyze_domain_compatibility_invalid_domains(self):
        """Test domain compatibility analysis with invalid domains."""
        analyzer = DomainCompatibilityAnalyzer()
        domains = ["", "invalid..domain", "*.*.double.wildcard"]

        with patch('re.match') as mock_match:
            # Mock invalid domains - re.match returns None for invalid domains
            mock_match.return_value = None

            result = analyzer.analyze_domain_compatibility(domains)

            assert result["total_domains"] == 3
            assert result["valid_count"] == 0
            assert result["invalid_count"] == 3
            assert result["compatibility_rate"] == 0.0
            assert result["valid_domains"] == []
            assert result["invalid_domains"] == domains
            assert "empty" in result["invalid_reasons"]
            # Note: The actual categorization logic puts all invalid domains in "invalid_characters"
            assert "invalid_characters" in result["invalid_reasons"]

    def test_analyze_domain_compatibility_mixed_domains(self):
        """Test domain compatibility analysis with mixed valid/invalid domains."""
        analyzer = DomainCompatibilityAnalyzer()
        domains = ["valid.com", "", "invalid..domain"]
        
        def mock_match_side_effect(pattern, domain):
            return domain == "valid.com"
        
        with patch('re.match', side_effect=mock_match_side_effect):
            result = analyzer.analyze_domain_compatibility(domains)
            
            assert result["total_domains"] == 3
            assert result["valid_count"] == 1
            assert result["invalid_count"] == 2
            assert result["compatibility_rate"] == 1/3
            assert result["valid_domains"] == ["valid.com"]
            assert result["invalid_domains"] == ["", "invalid..domain"]

    def test_analyze_domain_compatibility_empty_list(self):
        """Test domain compatibility analysis with empty domain list."""
        analyzer = DomainCompatibilityAnalyzer()
        domains = []
        
        result = analyzer.analyze_domain_compatibility(domains)
        
        assert result["total_domains"] == 0
        assert result["valid_count"] == 0
        assert result["invalid_count"] == 0
        assert result["compatibility_rate"] == 0
        assert result["valid_domains"] == []
        assert result["invalid_domains"] == []

    def test_analyze_webgroup_domains(self):
        """Test WebGroup domain compatibility analysis."""
        analyzer = DomainCompatibilityAnalyzer()
        
        webgroups_df = pd.DataFrame({
            "name": ["webgroup1", "webgroup2", "empty_group"],
            "domains": [
                ["valid.com", "invalid..com"],
                ["another.com"],
                []
            ]
        })
        
        def mock_analyze_compatibility(domains):
            if not domains:
                return {"total_domains": 0, "invalid_count": 0}
            return {
                "total_domains": len(domains),
                "invalid_count": 1 if "invalid..com" in domains else 0
            }
        
        with patch.object(analyzer, 'analyze_domain_compatibility', side_effect=mock_analyze_compatibility):
            result = analyzer.analyze_webgroup_domains(webgroups_df)
            
            assert "webgroup1" in result
            assert "webgroup2" in result
            assert "empty_group" not in result  # No domains
            
            assert result["webgroup1"]["total_domains"] == 2
            assert result["webgroup1"]["invalid_count"] == 1
            assert result["webgroup2"]["total_domains"] == 1
            assert result["webgroup2"]["invalid_count"] == 0


class TestFQDNAnalyzer:
    """Test the FQDNAnalyzer class."""

    def test_init_with_default_ports(self):
        """Test initialization with default web ports."""
        analyzer = FQDNAnalyzer()
        assert analyzer.categorizer.default_web_ports == {"80", "443"}
        assert isinstance(analyzer.domain_analyzer, DomainCompatibilityAnalyzer)

    def test_init_with_custom_ports(self):
        """Test initialization with custom web ports."""
        custom_ports = {"80", "443", "8080"}
        analyzer = FQDNAnalyzer(default_web_ports=custom_ports)
        assert analyzer.categorizer.default_web_ports == custom_ports

    def test_analyze_fqdn_rules_basic(self):
        """Test basic FQDN rules analysis."""
        analyzer = FQDNAnalyzer()
        
        fqdn_tag_rule_df = pd.DataFrame({
            "fqdn_tag_name": ["tag1", "tag2"],
            "fqdn": ["example.com", "test.com"],
            "protocol": ["tcp", "udp"],
            "port": ["443", "53"]
        })
        
        fqdn_df = pd.DataFrame({
            "fqdn_tag": ["tag1", "tag2"],
            "fqdn_enabled": [True, False],
            "fqdn_mode": ["white", "black"]
        })
        
        # Mock categorizer and domain analyzer
        mock_categories = {
            "webgroup_rules": pd.DataFrame([{"fqdn": "example.com"}]),
            "hostname_rules": pd.DataFrame(),
            "unsupported_rules": pd.DataFrame()
        }
        
        mock_domain_compat = {
            "valid_count": 2,
            "invalid_count": 0
        }
        
        with patch.object(analyzer.categorizer, 'categorize_by_protocol_port', return_value=mock_categories):
            with patch.object(analyzer.domain_analyzer, 'analyze_domain_compatibility', return_value=mock_domain_compat):
                result = analyzer.analyze_fqdn_rules(fqdn_tag_rule_df, fqdn_df)
                
                assert isinstance(result, FQDNAnalysisResult)
                assert result.total_rules == 2
                assert result.enabled_rules == 1  # Only tag1 enabled
                assert result.disabled_rules == 1  # Only tag2 disabled
                assert result.webgroup_rules == 1
                assert result.hostname_rules == 0
                assert result.unsupported_rules == 0
                assert result.unique_domains == 2
                assert result.dcf_compatible_domains == 2
                assert result.dcf_incompatible_domains == 0

    def test_analyze_fqdn_rules_empty_dataframes(self):
        """Test FQDN rules analysis with empty DataFrames."""
        analyzer = FQDNAnalyzer()

        empty_fqdn_tag_rule_df = pd.DataFrame(columns=[
            "protocol", "port", "mode", "enabled", "gateway"  # Add required columns
        ])
        empty_fqdn_df = pd.DataFrame()

        mock_categories = {
            "webgroup_rules": pd.DataFrame(),
            "hostname_rules": pd.DataFrame(),
            "unsupported_rules": pd.DataFrame()
        }

        mock_domain_compat = {
            "valid_count": 0,
            "invalid_count": 0
        }

        with patch.object(analyzer.categorizer, 'categorize_by_protocol_port', return_value=mock_categories):
            with patch.object(analyzer.domain_analyzer, 'analyze_domain_compatibility', return_value=mock_domain_compat):
                result = analyzer.analyze_fqdn_rules(empty_fqdn_tag_rule_df, empty_fqdn_df)
                
                assert result.total_rules == 0
                assert result.enabled_rules == 0
                assert result.disabled_rules == 0
                assert result.unique_domains == 0

    def test_analyze_fqdn_rules_with_gateway_breakdown(self):
        """Test FQDN rules analysis with gateway breakdown."""
        analyzer = FQDNAnalyzer()
        
        fqdn_tag_rule_df = pd.DataFrame({
            "fqdn_tag_name": ["tag1"],
            "fqdn": ["example.com"],
            "protocol": ["tcp"],
            "port": ["443"]
        })
        
        fqdn_df = pd.DataFrame({
            "fqdn_tag": ["tag1"],
            "fqdn_enabled": [True],
            "fqdn_mode": ["white"],
            "gw_filter_tag_list": [{"gw_name": "gateway1"}]
        })
        
        mock_categories = {
            "webgroup_rules": pd.DataFrame([{"fqdn": "example.com"}]),
            "hostname_rules": pd.DataFrame(),
            "unsupported_rules": pd.DataFrame()
        }
        
        mock_domain_compat = {"valid_count": 1, "invalid_count": 0}
        
        with patch.object(analyzer.categorizer, 'categorize_by_protocol_port', return_value=mock_categories):
            with patch.object(analyzer.domain_analyzer, 'analyze_domain_compatibility', return_value=mock_domain_compat):
                result = analyzer.analyze_fqdn_rules(fqdn_tag_rule_df, fqdn_df)
                
                assert result.gateway_breakdown == {"gateway1": 1}

    def test_generate_analysis_report(self):
        """Test generation of analysis report."""
        analyzer = FQDNAnalyzer()
        
        analysis_result = FQDNAnalysisResult(
            total_rules=100,
            enabled_rules=80,
            disabled_rules=20,
            webgroup_rules=30,
            hostname_rules=50,
            unsupported_rules=0,
            unique_domains=45,
            dcf_compatible_domains=42,
            dcf_incompatible_domains=3,
            protocol_breakdown={"tcp": 70, "udp": 10},
            port_breakdown={"443": 30, "80": 20},
            mode_breakdown={"white": 60, "black": 20},
            gateway_breakdown={"gw1": 40, "gw2": 40}
        )
        
        report = analyzer.generate_analysis_report(analysis_result)
        
        assert "summary" in report
        assert "dcf_translation" in report
        assert "domain_analysis" in report
        assert "breakdowns" in report
        
        assert report["summary"]["total_fqdn_rules"] == 100
        assert report["summary"]["enabled_rules"] == 80
        assert report["summary"]["enablement_rate"] == 0.8
        
        assert report["dcf_translation"]["webgroup_rules"] == 30
        assert report["dcf_translation"]["hostname_smartgroup_rules"] == 50
        assert report["dcf_translation"]["webgroup_rate"] == 30/80  # 30 webgroup / 80 enabled
        
        assert report["domain_analysis"]["unique_domains"] == 45
        assert report["domain_analysis"]["compatibility_rate"] == 42/45

    def test_generate_analysis_report_zero_division_handling(self):
        """Test analysis report generation with zero values to avoid division by zero."""
        analyzer = FQDNAnalyzer()
        
        analysis_result = FQDNAnalysisResult(
            total_rules=0,
            enabled_rules=0,
            disabled_rules=0,
            webgroup_rules=0,
            hostname_rules=0,
            unsupported_rules=0,
            unique_domains=0,
            dcf_compatible_domains=0,
            dcf_incompatible_domains=0,
            protocol_breakdown={},
            port_breakdown={},
            mode_breakdown={},
            gateway_breakdown={}
        )
        
        report = analyzer.generate_analysis_report(analysis_result)
        
        # Should handle zero division gracefully
        assert report["summary"]["enablement_rate"] == 0
        assert report["dcf_translation"]["webgroup_rate"] == 0
        assert report["dcf_translation"]["hostname_rate"] == 0
        assert report["domain_analysis"]["compatibility_rate"] == 0

    def test_log_analysis_summary(self):
        """Test logging of analysis summary."""
        analyzer = FQDNAnalyzer()
        
        analysis_result = FQDNAnalysisResult(
            total_rules=100,
            enabled_rules=80,
            disabled_rules=20,
            webgroup_rules=30,
            hostname_rules=50,
            unsupported_rules=0,
            unique_domains=45,
            dcf_compatible_domains=42,
            dcf_incompatible_domains=3,
            protocol_breakdown={"tcp": 70},
            port_breakdown={"443": 30},
            mode_breakdown={"white": 60},
            gateway_breakdown={"gw1": 40}
        )
        
        with patch.object(analyzer.logger, 'info') as mock_info:
            with patch.object(analyzer.logger, 'warning') as mock_warning:
                analyzer.log_analysis_summary(analysis_result)
                
                # Should log summary info
                assert mock_info.call_count >= 8  # Multiple info messages
                
                # Should log warning for incompatible domains
                mock_warning.assert_called_once()
                warning_call = mock_warning.call_args[0][0]
                assert "3 domains incompatible" in warning_call

    def test_log_analysis_summary_no_incompatible_domains(self):
        """Test logging when no incompatible domains exist."""
        analyzer = FQDNAnalyzer()
        
        analysis_result = FQDNAnalysisResult(
            total_rules=50,
            enabled_rules=40,
            disabled_rules=10,
            webgroup_rules=20,
            hostname_rules=20,
            unsupported_rules=0,
            unique_domains=30,
            dcf_compatible_domains=30,
            dcf_incompatible_domains=0,  # No incompatible domains
            protocol_breakdown={"tcp": 35},
            port_breakdown={"443": 20},
            mode_breakdown={"white": 40},
            gateway_breakdown={"gw1": 25}
        )
        
        with patch.object(analyzer.logger, 'info') as mock_info:
            with patch.object(analyzer.logger, 'warning') as mock_warning:
                analyzer.log_analysis_summary(analysis_result)
                
                # Should log summary info
                assert mock_info.call_count >= 8
                
                # Should not log warning when no incompatible domains
                mock_warning.assert_not_called()
