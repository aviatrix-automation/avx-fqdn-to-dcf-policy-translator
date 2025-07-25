"""
Unit tests for WebGroup creation and management module.

This module tests the WebGroupBuilder and WebGroupManager classes responsible for
translating FQDN tag rules to WebGroups for HTTP/HTTPS traffic optimization.
"""

import logging
import pytest
import pandas as pd
from unittest.mock import patch, MagicMock

import sys
from pathlib import Path

# Add the src directory to Python path for imports
sys.path.append(str(Path(__file__).parent.parent.parent.parent / 'src'))

from src.translation.webgroups import WebGroupBuilder, WebGroupManager, build_webgroup_df, translate_fqdn_tag_to_sg_selector
from src.config import TranslationConfig


class TestWebGroupBuilder:
    """Test the WebGroupBuilder class."""

    def test_init(self):
        """Test WebGroupBuilder initialization."""
        builder = WebGroupBuilder()
        
        assert builder.all_invalid_domains == []
        assert builder.cleaner is not None

    def test_create_webgroup_name_basic(self):
        """Test WebGroup name creation with basic inputs."""
        builder = WebGroupBuilder()
        
        # Test with standard inputs
        row = pd.Series({
            'fqdn_tag_name': 'web-servers',
            'protocol': 'tcp',
            'port': '443',
            'fqdn_mode': 'white'
        })
        
        result = builder.create_webgroup_name(row)
        assert result == 'web-servers_permit_tcp_443'

    def test_create_webgroup_name_black_mode(self):
        """Test WebGroup name creation with black mode."""
        builder = WebGroupBuilder()
        
        row = pd.Series({
            'fqdn_tag_name': 'blocked-sites',
            'protocol': 'tcp',
            'port': '80',
            'fqdn_mode': 'black'
        })
        
        result = builder.create_webgroup_name(row)
        assert result == 'blocked-sites_deny_tcp_80'

    def test_create_webgroup_name_unknown_mode(self):
        """Test WebGroup name creation with unknown mode."""
        builder = WebGroupBuilder()
        
        row = pd.Series({
            'fqdn_tag_name': 'test-tag',
            'protocol': 'tcp',
            'port': '8080',
            'fqdn_mode': 'unknown_mode'
        })
        
        result = builder.create_webgroup_name(row)
        assert result == 'test-tag_unknown_mode_tcp_8080'

    def test_translate_fqdn_to_selector_basic(self):
        """Test FQDN list to selector translation."""
        builder = WebGroupBuilder()

        fqdn_list = ['example.com', 'test.com']
        result = builder._translate_fqdn_to_selector(fqdn_list)

        expected = {
            'match_expressions': [
                {'snifilter': 'example.com'},
                {'snifilter': 'test.com'}
            ]
        }
        assert result == expected

    def test_translate_fqdn_to_selector_empty_list(self):
        """Test FQDN list to selector translation with empty list."""
        builder = WebGroupBuilder()

        result = builder._translate_fqdn_to_selector([])

        expected = {
            'match_expressions': []
        }
        assert result == expected

    def test_translate_fqdn_to_selector_single_domain(self):
        """Test FQDN list to selector translation with single domain."""
        builder = WebGroupBuilder()
        
        result = builder._translate_fqdn_to_selector(['single.com'])
        
        expected = {
            'match_expressions': [
                {'snifilter': 'single.com'}
            ]
        }
        assert result == expected

    @patch('src.translation.webgroups.FQDNValidator.filter_domains_for_dcf_compatibility')
    def test_filter_and_create_selector_valid_domains(self, mock_filter):
        """Test filtering and selector creation with valid domains."""
        builder = WebGroupBuilder()

        # Mock the filter to return all domains as valid
        mock_filter.return_value = (['example.com', 'test.com'], [])

        row = pd.Series({
            'name': 'test-webgroup',
            'fqdn': ['example.com', 'test.com'],
            'fqdn_tag_name': 'test-tag',
            'protocol': 'tcp',
            'port': '443'
        })

        result = builder.filter_and_create_selector(row)
        
        expected = {
            'match_expressions': [
                {'type': 'fqdn', 'fqdn': ['example.com', 'test.com']}
            ]
        }
        assert result == expected
        assert builder.all_invalid_domains == []    @patch('src.translation.webgroups.FQDNValidator.filter_domains_for_dcf_compatibility')
    def test_filter_and_create_selector_some_invalid(self, mock_filter):
        """Test filtering and selector creation with some invalid domains."""
        builder = WebGroupBuilder()

        # Mock the filter to return some domains as invalid
        mock_filter.return_value = (['example.com'], ['invalid..domain'])

        row = pd.Series({
            'name': 'test-webgroup',
            'fqdn': ['example.com', 'invalid..domain'],
            'fqdn_tag_name': 'test-tag',
            'protocol': 'tcp',
            'port': '443'
        })

        result = builder.filter_and_create_selector(row)
        
        expected = {
            'match_expressions': [
                {'type': 'fqdn', 'fqdn': ['example.com']}
            ]
        }
        assert result == expected
        
        # Check invalid domains were stored
        assert len(builder.all_invalid_domains) == 1
        assert builder.all_invalid_domains[0] == {
            'webgroup': 'test-webgroup',
            'domain': 'invalid..domain'
        }

    def test_build_webgroup_dataframe_empty_input(self):
        """Test WebGroup DataFrame building with empty input."""
        builder = WebGroupBuilder()
        
        empty_df = pd.DataFrame()
        result = builder.build_webgroup_dataframe(empty_df)
        
        assert len(result) == 0
        assert list(result.columns) == ['name', 'selector']

    @patch('src.translation.webgroups.FQDNValidator.filter_domains_for_dcf_compatibility')
    def test_build_webgroup_dataframe_basic(self, mock_filter):
        """Test WebGroup DataFrame building with basic input."""
        builder = WebGroupBuilder()
        
        # Mock the filter to return all domains as valid
        mock_filter.return_value = (['example.com', 'test.com'], [])
        
        # Mock the cleaner method
        with patch.object(builder.cleaner, 'remove_invalid_name_chars') as mock_clean:
            mock_clean.return_value = pd.DataFrame({
                'name': ['web-servers_permit_tcp_443'],
                'selector': [{
                    'match_expressions': [
                        {'type': 'fqdn', 'fqdn': ['example.com', 'test.com']}
                    ]
                }]
            })
            
            fqdn_df = pd.DataFrame({
                'fqdn_tag_name': ['web-servers', 'web-servers'],
                'fqdn': ['example.com', 'test.com'],
                'protocol': ['tcp', 'tcp'],
                'port': ['443', '443'],
                'fqdn_mode': ['white', 'white']
            })
            
            result = builder.build_webgroup_dataframe(fqdn_df)
            
            assert len(result) == 1
            assert result.iloc[0]['name'] == 'web-servers_permit_tcp_443'
            assert 'match_expressions' in result.iloc[0]['selector']

    @patch('src.translation.webgroups.FQDNValidator.filter_domains_for_dcf_compatibility')
    def test_build_webgroup_dataframe_multiple_groups(self, mock_filter):
        """Test WebGroup DataFrame building with multiple groups."""
        builder = WebGroupBuilder()
        
        # Mock the filter to return all domains as valid
        mock_filter.return_value = (['example.com'], [])
        
        # Mock the cleaner method
        with patch.object(builder.cleaner, 'remove_invalid_name_chars') as mock_clean:
            def mock_clean_side_effect(df, column):
                # Return the DataFrame as-is for this test
                return df
            mock_clean.side_effect = mock_clean_side_effect
            
            fqdn_df = pd.DataFrame({
                'fqdn_tag_name': ['web-servers', 'api-servers'],
                'fqdn': ['example.com', 'api.com'],
                'protocol': ['tcp', 'tcp'],
                'port': ['443', '8080'],
                'fqdn_mode': ['white', 'black']
            })
            
            result = builder.build_webgroup_dataframe(fqdn_df)
            
            assert len(result) == 2
            assert 'web-servers_permit_tcp_443' in result['name'].values
            assert 'api-servers_deny_tcp_8080' in result['name'].values

    def test_log_filtered_domains_no_invalid(self, caplog):
        """Test logging when no domains are filtered."""
        builder = WebGroupBuilder()
        
        with caplog.at_level(logging.WARNING):
            builder._log_filtered_domains()
        
        # No warning messages should be logged
        assert len(caplog.records) == 0

    def test_log_filtered_domains_with_invalid(self, caplog):
        """Test logging when domains are filtered."""
        builder = WebGroupBuilder()
        
        # Add some invalid domains
        builder.all_invalid_domains = [
            {'webgroup': 'test-group', 'domain': 'invalid..domain'},
            {'webgroup': 'test-group', 'domain': 'another..invalid'},
            {'webgroup': 'other-group', 'domain': 'bad..domain'}
        ]
        
        with caplog.at_level(logging.WARNING):
            builder._log_filtered_domains()
        
        # Check that warning messages were logged
        warning_messages = [record.message for record in caplog.records if record.levelno == logging.WARNING]
        assert len(warning_messages) == 3  # One general message + 2 group-specific messages
        assert 'Total DCF 8.0 incompatible SNI domains filtered: 3' in warning_messages[0]
        assert 'test-group' in warning_messages[1]
        assert 'other-group' in warning_messages[2]


class TestWebGroupManager:
    """Test the WebGroupManager class."""

    def test_init(self):
        """Test WebGroupManager initialization."""
        manager = WebGroupManager()
        
        assert manager.builder is not None
        assert isinstance(manager.builder, WebGroupBuilder)

    @patch.object(WebGroupBuilder, 'build_webgroup_dataframe')
    def test_create_webgroups_from_fqdn_rules(self, mock_build):
        """Test WebGroup creation from FQDN rules."""
        manager = WebGroupManager()
        
        # Mock the builder method
        mock_build.return_value = pd.DataFrame({
            'name': ['test-webgroup'],
            'selector': [{'match_expressions': [{'type': 'fqdn', 'fqdn': ['example.com']}]}]
        })
        
        fqdn_df = pd.DataFrame({
            'fqdn_tag_name': ['web-servers'],
            'fqdn': ['example.com'],
            'protocol': ['tcp'],
            'port': ['443'],
            'fqdn_mode': ['white']
        })
        
        result = manager.create_webgroups_from_fqdn_rules(fqdn_df)
        
        assert len(result) == 1
        assert result.iloc[0]['name'] == 'test-webgroup'
        mock_build.assert_called_once_with(fqdn_df)

    def test_validate_webgroup_constraints_all_valid(self):
        """Test WebGroup constraint validation with all valid groups."""
        manager = WebGroupManager()
        
        webgroups_df = pd.DataFrame({
            'name': ['short-name', 'another-valid-name'],
            'selector': [{'test': 'selector1'}, {'test': 'selector2'}]
        })
        
        result = manager.validate_webgroup_constraints(webgroups_df)
        
        assert len(result) == 2
        assert result.equals(webgroups_df)

    def test_validate_webgroup_constraints_some_invalid(self, caplog):
        """Test WebGroup constraint validation with some invalid groups."""
        manager = WebGroupManager()
        
        # Create a name that's too long (over 256 characters)
        long_name = 'x' * 300
        
        webgroups_df = pd.DataFrame({
            'name': ['short-name', long_name, 'another-valid-name'],
            'selector': [{'test': 'selector1'}, {'test': 'selector2'}, {'test': 'selector3'}]
        })
        
        with caplog.at_level(logging.WARNING):
            result = manager.validate_webgroup_constraints(webgroups_df)
        
        # Should only keep the valid names
        assert len(result) == 2
        assert 'short-name' in result['name'].values
        assert 'another-valid-name' in result['name'].values
        assert long_name not in result['name'].values
        
        # Check warning messages
        warning_messages = [record.message for record in caplog.records if record.levelno == logging.WARNING]
        assert len(warning_messages) >= 2  # At least the summary and specific name warnings
        assert 'Found 1 WebGroups with names exceeding' in warning_messages[0]
        assert 'Removed 1 WebGroups due to constraint violations' in warning_messages[-1]

    def test_validate_webgroup_constraints_empty_input(self):
        """Test WebGroup constraint validation with empty input."""
        manager = WebGroupManager()
        
        empty_df = pd.DataFrame(columns=['name', 'selector'])
        result = manager.validate_webgroup_constraints(empty_df)
        
        assert len(result) == 0
        assert list(result.columns) == ['name', 'selector']


class TestLegacyFunctions:
    """Test legacy wrapper functions for backward compatibility."""

    @patch.object(WebGroupManager, 'create_webgroups_from_fqdn_rules')
    def test_build_webgroup_df_legacy_wrapper(self, mock_create):
        """Test the legacy build_webgroup_df function."""
        mock_create.return_value = pd.DataFrame({
            'name': ['test-webgroup'],
            'selector': [{'test': 'selector'}]
        })
        
        fqdn_df = pd.DataFrame({
            'fqdn_tag_name': ['web-servers'],
            'fqdn': ['example.com'],
            'protocol': ['tcp'],
            'port': ['443'],
            'fqdn_mode': ['white']
        })
        
        result = build_webgroup_df(fqdn_df)
        
        assert len(result) == 1
        assert result.iloc[0]['name'] == 'test-webgroup'
        mock_create.assert_called_once_with(fqdn_df)

    def test_translate_fqdn_tag_to_sg_selector_legacy_wrapper(self):
        """Test the legacy translate_fqdn_tag_to_sg_selector function."""
        fqdn_list = ['example.com', 'test.com']
        result = translate_fqdn_tag_to_sg_selector(fqdn_list)

        expected = {
            'match_expressions': [
                {'snifilter': 'example.com'},
                {'snifilter': 'test.com'}
            ]
        }
        assert result == expected


class TestWebGroupBuilderIntegration:
    """Integration tests for WebGroupBuilder combining multiple features."""

    @patch('src.translation.webgroups.FQDNValidator.filter_domains_for_dcf_compatibility')
    def test_full_webgroup_creation_pipeline(self, mock_filter):
        """Test the complete WebGroup creation pipeline."""
        builder = WebGroupBuilder()
        
        # Mock domain filtering with mixed results
        def mock_filter_side_effect(domains, webgroup_name):
            valid = [d for d in domains if not d.startswith('invalid')]
            invalid = [d for d in domains if d.startswith('invalid')]
            return valid, invalid
        
        mock_filter.side_effect = mock_filter_side_effect
        
        # Mock the cleaner method
        with patch.object(builder.cleaner, 'remove_invalid_name_chars') as mock_clean:
            def mock_clean_side_effect(df, column):
                return df  # Return as-is for this test
            mock_clean.side_effect = mock_clean_side_effect
            
            fqdn_df = pd.DataFrame({
                'fqdn_tag_name': ['web-servers', 'web-servers', 'api-servers'],
                'fqdn': ['example.com', 'invalid.domain', 'api.example.com'],
                'protocol': ['tcp', 'tcp', 'tcp'],
                'port': ['443', '443', '8080'],
                'fqdn_mode': ['white', 'white', 'black']
            })
            
            result = builder.build_webgroup_dataframe(fqdn_df)
            
            # Should create 2 WebGroups (grouped by tag/protocol/port/mode)
            assert len(result) == 2
            
            # Check that invalid domains were tracked
            assert len(builder.all_invalid_domains) == 1
            assert builder.all_invalid_domains[0]['domain'] == 'invalid.domain'

    def test_error_handling_with_malformed_data(self):
        """Test error handling with malformed input data."""
        builder = WebGroupBuilder()
        
        # DataFrame missing required columns
        malformed_df = pd.DataFrame({
            'fqdn_tag_name': ['test'],
            # Missing other required columns
        })
        
        # Should handle missing columns gracefully
        with pytest.raises(KeyError):
            builder.build_webgroup_dataframe(malformed_df)

    @patch('src.translation.webgroups.FQDNValidator.filter_domains_for_dcf_compatibility')
    def test_name_cleaning_integration(self, mock_filter):
        """Test integration with name cleaning functionality."""
        builder = WebGroupBuilder()
        
        # Mock domain filtering to return all as valid
        mock_filter.return_value = (['example.com'], [])
        
        # Mock the cleaner to simulate name cleaning
        with patch.object(builder.cleaner, 'remove_invalid_name_chars') as mock_clean:
            def mock_clean_side_effect(df, column):
                # Simulate cleaning by replacing invalid characters
                df = df.copy()
                df[column] = df[column].str.replace('!', '_')
                return df
            mock_clean.side_effect = mock_clean_side_effect
            
            fqdn_df = pd.DataFrame({
                'fqdn_tag_name': ['web-servers!'],  # Invalid character
                'fqdn': ['example.com'],
                'protocol': ['tcp'],
                'port': ['443'],
                'fqdn_mode': ['white']
            })
            
            result = builder.build_webgroup_dataframe(fqdn_df)
            
            assert len(result) == 1
            # Name should be cleaned
            assert '!' not in result.iloc[0]['name']
            assert 'web-servers_' in result.iloc[0]['name']
