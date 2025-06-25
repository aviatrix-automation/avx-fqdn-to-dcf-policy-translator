"""
Unit tests for translation reporting module.

Tests the TranslationStats dataclass and TranslationReporter class for
generating comprehensive reports on translation results and analysis.
"""

import pytest
import pandas as pd
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock
from typing import Dict, Any

from src.analysis.translation_reporter import (
    TranslationStats,
    TranslationReporter
)
from src.analysis.fqdn_analysis import FQDNAnalysisResult
from src.analysis.policy_validators import ValidationResult


class TestTranslationStats:
    """Test the TranslationStats dataclass."""

    def test_translation_stats_creation_basic(self):
        """Test creating TranslationStats with basic fields."""
        input_counts = {"fw_policy": 100, "fw_tag": 50}
        output_counts = {"smartgroups": 25, "webgroups": 15}
        
        stats = TranslationStats(
            input_counts=input_counts,
            output_counts=output_counts
        )

        assert stats.input_counts == input_counts
        assert stats.output_counts == output_counts
        assert stats.processing_time is None
        assert stats.timestamp is None

    def test_translation_stats_creation_full(self):
        """Test creating TranslationStats with all fields."""
        input_counts = {"fw_policy": 100, "fw_tag": 50}
        output_counts = {"smartgroups": 25, "webgroups": 15}
        processing_time = 45.5
        timestamp = "2024-01-01T12:00:00"
        
        stats = TranslationStats(
            input_counts=input_counts,
            output_counts=output_counts,
            processing_time=processing_time,
            timestamp=timestamp
        )

        assert stats.input_counts == input_counts
        assert stats.output_counts == output_counts
        assert stats.processing_time == processing_time
        assert stats.timestamp == timestamp


class TestTranslationReporter:
    """Test the TranslationReporter class."""

    def test_init(self):
        """Test initialization of TranslationReporter."""
        output_dir = Path("/tmp/test_output")
        reporter = TranslationReporter(output_dir)
        
        assert reporter.output_dir == output_dir
        assert hasattr(reporter, 'logger')

    def test_generate_summary_statistics_basic(self):
        """Test generation of summary statistics from translation data."""
        reporter = TranslationReporter(Path("/tmp"))
        
        # Create mock DataFrames
        fw_policy_df = pd.DataFrame([{"src_ip": "192.168.1.1"}] * 100)
        fw_tag_df = pd.DataFrame([{"firewall_tag": "tag1"}] * 50)
        smartgroups_df = pd.DataFrame([{"name": "sg1"}] * 25)
        webgroups_df = pd.DataFrame([{"name": "wg1"}] * 15)
        
        data = {
            "fw_policy_df": fw_policy_df,
            "fw_tag_df": fw_tag_df,
            "fqdn_df": pd.DataFrame([{"fqdn_tag": "fqdn1"}] * 30),
            "fqdn_tag_rule_df": pd.DataFrame([{"fqdn": "example.com"}] * 80),
            "smartgroups_df": smartgroups_df,
            "webgroups_df": webgroups_df,
            "hostname_policies_df": pd.DataFrame([{"policy": "p1"}] * 40),
            "full_policy_list": [{"policy": "p1"}] * 120
        }
        
        with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
            mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T12:00:00"
            
            stats = reporter.generate_summary_statistics(data)
            
            assert isinstance(stats, TranslationStats)
            assert stats.input_counts["fw_policy"] == 100
            assert stats.input_counts["fw_tag"] == 50
            assert stats.input_counts["fqdn"] == 30
            assert stats.input_counts["fqdn_tag_rule"] == 80
            assert stats.output_counts["smartgroups"] == 25
            assert stats.output_counts["webgroups"] == 15
            assert stats.output_counts["hostname_policies"] == 40
            assert stats.output_counts["full_policy"] == 120
            assert stats.timestamp == "2024-01-01T12:00:00"

    def test_generate_summary_statistics_missing_data(self):
        """Test summary statistics generation with missing data."""
        reporter = TranslationReporter(Path("/tmp"))
        
        # Data with missing keys
        data = {
            "fw_policy_df": pd.DataFrame([{"src_ip": "192.168.1.1"}] * 10),
            # Missing other expected keys
        }
        
        with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
            mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T12:00:00"
            
            stats = reporter.generate_summary_statistics(data)
            
            assert stats.input_counts["fw_policy"] == 10
            assert stats.input_counts["fw_tag"] == 0
            assert stats.input_counts["fqdn"] == 0
            assert stats.input_counts["fqdn_tag_rule"] == 0

    def test_generate_summary_statistics_non_dataframe_values(self):
        """Test summary statistics with non-DataFrame values."""
        reporter = TranslationReporter(Path("/tmp"))

        data = {
            "fw_policy_df": "not_a_dataframe",
            "fw_tag_df": None,
            "smartgroups_df": pd.DataFrame([{"name": "sg1"}] * 5)
        }

        with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
            mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T12:00:00"

            stats = reporter.generate_summary_statistics(data)

            # The implementation uses len() on any object with __len__, so:
            # - "not_a_dataframe" (string) has length 15
            # - None has no __len__ so should be 0
            # - smartgroups_df has 5 rows
            assert stats.input_counts["fw_policy"] == 15  # len("not_a_dataframe")
            assert stats.input_counts["fw_tag"] == 0  # None has no __len__
            assert stats.output_counts["smartgroups"] == 5
            assert stats.input_counts["fw_tag"] == 0
            assert stats.output_counts["smartgroups"] == 5

    def test_generate_fqdn_report(self):
        """Test generation of FQDN analysis report."""
        reporter = TranslationReporter(Path("/tmp"))
        
        fqdn_analysis = FQDNAnalysisResult(
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
        
        report = reporter.generate_fqdn_report(fqdn_analysis)
        
        assert "fqdn_summary" in report
        assert "dcf_translation_breakdown" in report
        assert "domain_compatibility" in report
        assert "breakdown_analysis" in report
        
        # Check fqdn_summary
        assert report["fqdn_summary"]["total_fqdn_rules"] == 100
        assert report["fqdn_summary"]["enabled_rules"] == 80
        assert report["fqdn_summary"]["disabled_rules"] == 20
        assert report["fqdn_summary"]["enablement_rate"] == 0.8
        
        # Check dcf_translation_breakdown
        assert report["dcf_translation_breakdown"]["webgroup_rules"] == 30
        assert report["dcf_translation_breakdown"]["hostname_smartgroup_rules"] == 50
        assert report["dcf_translation_breakdown"]["unsupported_rules"] == 0
        assert report["dcf_translation_breakdown"]["webgroup_percentage"] == 30/80 * 100
        assert report["dcf_translation_breakdown"]["hostname_percentage"] == 50/80 * 100
        
        # Check domain_compatibility
        assert report["domain_compatibility"]["unique_domains"] == 45
        assert report["domain_compatibility"]["dcf_compatible_domains"] == 42
        assert report["domain_compatibility"]["dcf_incompatible_domains"] == 3
        assert report["domain_compatibility"]["compatibility_rate"] == 42/45
        
        # Check breakdown_analysis
        assert report["breakdown_analysis"]["protocols"] == {"tcp": 70, "udp": 10}
        assert report["breakdown_analysis"]["ports"] == {"443": 30, "80": 20}
        assert report["breakdown_analysis"]["modes"] == {"white": 60, "black": 20}
        assert report["breakdown_analysis"]["gateways"] == {"gw1": 40, "gw2": 40}

    def test_generate_validation_report(self):
        """Test generation of validation report."""
        reporter = TranslationReporter(Path("/tmp"))
        
        validation_result = ValidationResult(
            total_policies=100,
            issues_found=25,
            stateless_issues=5,
            unused_tags={"unused1", "unused2"},
            single_cidr_tags={"192.168.1.0/24": "cidr_tag1"},
            duplicate_policies=10,
            validation_warnings=["Warning 1", "Warning 2"],
            validation_errors=["Error 1"]
        )
        
        report = reporter.generate_validation_report(validation_result)
        
        assert "validation_summary" in report
        assert "issue_breakdown" in report
        assert "detailed_findings" in report
        
        # Check validation_summary
        assert report["validation_summary"]["total_policies_analyzed"] == 100
        assert report["validation_summary"]["total_issues_found"] == 25
        assert report["validation_summary"]["validation_success_rate"] == 1 - (25/100)
        
        # Check issue_breakdown
        assert report["issue_breakdown"]["stateless_policy_issues"] == 5
        assert report["issue_breakdown"]["unused_firewall_tags"] == 2
        assert report["issue_breakdown"]["single_cidr_tags_found"] == 1
        assert report["issue_breakdown"]["duplicate_policies"] == 10
        assert report["issue_breakdown"]["validation_warnings"] == 2
        assert report["issue_breakdown"]["validation_errors"] == 1
        
        # Check detailed_findings
        assert set(report["detailed_findings"]["unused_tags"]) == {"unused1", "unused2"}
        assert report["detailed_findings"]["single_cidr_mappings"] == {"192.168.1.0/24": "cidr_tag1"}
        assert report["detailed_findings"]["warnings"] == ["Warning 1", "Warning 2"]
        assert report["detailed_findings"]["errors"] == ["Error 1"]

    def test_generate_comprehensive_report_basic(self):
        """Test generation of comprehensive report without optional analyses."""
        reporter = TranslationReporter(Path("/tmp"))
        
        data = {
            "fw_policy_df": pd.DataFrame([{"src_ip": "192.168.1.1"}] * 50),
            "smartgroups_df": pd.DataFrame([{"name": "sg1"}] * 10)
        }
        
        with patch.object(reporter, 'generate_summary_statistics') as mock_stats:
            with patch.object(reporter, '_calculate_completion_rate') as mock_completion:
                with patch.object(reporter, '_calculate_data_coverage') as mock_coverage:
                    with patch.object(reporter, '_generate_recommendations') as mock_recommendations:
                        
                        mock_stats.return_value = TranslationStats(
                            input_counts={"fw_policy": 50},
                            output_counts={"smartgroups": 10}
                        )
                        mock_completion.return_value = 0.9
                        mock_coverage.return_value = 0.8
                        mock_recommendations.return_value = ["Recommendation 1"]
                        
                        with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
                            mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T12:00:00"
                            
                            report = reporter.generate_comprehensive_report(data)
                            
                            assert "report_metadata" in report
                            assert "translation_summary" in report
                            assert "success_metrics" in report
                            assert "recommendations" in report
                            
                            assert report["report_metadata"]["generated_at"] == "2024-01-01T12:00:00"
                            assert report["report_metadata"]["report_version"] == "1.0"
                            assert report["report_metadata"]["translator_type"] == "legacy-to-dcf"
                            
                            assert report["success_metrics"]["translation_completion_rate"] == 0.9
                            assert report["success_metrics"]["data_coverage"] == 0.8
                            
                            assert report["recommendations"]["items"] == ["Recommendation 1"]

    def test_generate_comprehensive_report_with_analyses(self):
        """Test comprehensive report generation with FQDN and validation analyses."""
        reporter = TranslationReporter(Path("/tmp"))
        
        data = {"fw_policy_df": pd.DataFrame([{"src_ip": "192.168.1.1"}])}
        
        fqdn_analysis = FQDNAnalysisResult(
            total_rules=50, enabled_rules=40, disabled_rules=10,
            webgroup_rules=20, hostname_rules=20, unsupported_rules=0,
            unique_domains=30, dcf_compatible_domains=28, dcf_incompatible_domains=2,
            protocol_breakdown={}, port_breakdown={}, mode_breakdown={}, gateway_breakdown={}
        )
        
        validation_result = ValidationResult(
            total_policies=50, issues_found=5, stateless_issues=2,
            unused_tags=set(), single_cidr_tags={}, duplicate_policies=3,
            validation_warnings=[], validation_errors=[]
        )
        
        with patch.object(reporter, 'generate_summary_statistics') as mock_stats:
            with patch.object(reporter, 'generate_fqdn_report') as mock_fqdn:
                with patch.object(reporter, 'generate_validation_report') as mock_validation:
                    with patch.object(reporter, '_calculate_completion_rate', return_value=0.9):
                        with patch.object(reporter, '_calculate_data_coverage', return_value=0.8):
                            with patch.object(reporter, '_generate_recommendations', return_value=["Rec 1"]):
                                
                                mock_stats.return_value = TranslationStats(
                                    input_counts={"fw_policy": 50},
                                    output_counts={"smartgroups": 10}
                                )
                                mock_fqdn.return_value = {"fqdn_summary": {"total_fqdn_rules": 50}}
                                mock_validation.return_value = {"validation_summary": {"total_policies_analyzed": 50}}
                                
                                with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
                                    mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T12:00:00"
                                    
                                    report = reporter.generate_comprehensive_report(
                                        data, fqdn_analysis, validation_result
                                    )
                                    
                                    assert "fqdn_analysis" in report
                                    assert "validation_analysis" in report
                                    assert report["fqdn_analysis"]["fqdn_summary"]["total_fqdn_rules"] == 50
                                    assert report["validation_analysis"]["validation_summary"]["total_policies_analyzed"] == 50

    def test_export_report_to_json_success(self):
        """Test successful export of report to JSON file."""
        output_dir = Path("/tmp/test_output")
        reporter = TranslationReporter(output_dir)
        
        report = {
            "test_key": "test_value",
            "nested": {"key": "value"}
        }
        
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('json.dump') as mock_json_dump:
                with patch('pathlib.Path.mkdir') as mock_mkdir:
                    with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
                        mock_datetime.now.return_value.strftime.return_value = "20240101_120000"
                        
                        result_path = reporter.export_report_to_json(report)
                        
                        expected_filename = "translation_report_20240101_120000.json"
                        expected_path = output_dir / expected_filename
                        
                        assert result_path == expected_path
                        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
                        mock_file.assert_called_once_with(expected_path, "w")
                        mock_json_dump.assert_called_once_with(report, mock_file(), indent=2, default=str)

    def test_export_report_to_json_custom_filename(self):
        """Test export with custom filename."""
        output_dir = Path("/tmp/test_output")
        reporter = TranslationReporter(output_dir)
        
        report = {"test": "data"}
        custom_filename = "custom_report.json"
        
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('json.dump') as mock_json_dump:
                with patch('pathlib.Path.mkdir') as mock_mkdir:
                    
                    result_path = reporter.export_report_to_json(report, custom_filename)
                    
                    expected_path = output_dir / custom_filename
                    assert result_path == expected_path
                    mock_file.assert_called_once_with(expected_path, "w")

    def test_export_report_to_json_error_handling(self):
        """Test error handling during JSON export."""
        output_dir = Path("/tmp/test_output")
        reporter = TranslationReporter(output_dir)
        
        report = {"test": "data"}
        
        with patch('builtins.open', side_effect=IOError("Permission denied")):
            with patch('pathlib.Path.mkdir'):
                with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
                    mock_datetime.now.return_value.strftime.return_value = "20240101_120000"
                    
                    with pytest.raises(IOError):
                        reporter.export_report_to_json(report)

    def test_export_summary_to_text_basic(self):
        """Test export of summary to text file."""
        output_dir = Path("/tmp/test_output")
        reporter = TranslationReporter(output_dir)

        report = {
            "report_metadata": {
                "generated_at": "2024-01-01T12:00:00",
                "report_version": "1.0"
            },
            "translation_summary": {
                "input_counts": {"fw_policy": 100, "fw_tag": 50},
                "output_counts": {"smartgroups": 25, "webgroups": 15}
            }
        }

        # Use mock_open to properly capture file writes
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('pathlib.Path.mkdir') as mock_mkdir:
                with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
                    mock_datetime.now.return_value.strftime.return_value = "20240101_120000"

                    result_path = reporter.export_summary_to_text(report)

                    expected_filename = "translation_summary_20240101_120000.txt"
                    expected_path = output_dir / expected_filename

                    assert result_path == expected_path
                    mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
                    mock_file.assert_called_once_with(expected_path, "w")

                    # Check that content was written using the file handle's write calls
                    handle = mock_file.return_value
                    written_calls = [call.args[0] for call in handle.write.call_args_list]
                    written_content = "".join(written_calls)
                    assert "LEGACY TO DCF POLICY TRANSLATION REPORT" in written_content
                    assert "Generated: 2024-01-01T12:00:00" in written_content
                    assert "fw_policy: 100" in written_content
                    assert "smartgroups: 25" in written_content

    def test_export_summary_to_text_with_fqdn_analysis(self):
        """Test text export with FQDN analysis included."""
        output_dir = Path("/tmp/test_output")
        reporter = TranslationReporter(output_dir)

        report = {
            "report_metadata": {"generated_at": "2024-01-01T12:00:00"},
            "fqdn_analysis": {
                "fqdn_summary": {
                    "total_fqdn_rules": 100,
                    "enabled_rules": 80,
                    "enablement_rate": 0.8
                },
                "dcf_translation_breakdown": {
                    "webgroup_rules": 30,
                    "hostname_smartgroup_rules": 50,
                    "unsupported_rules": 0
                }
            }
        }

        with patch('builtins.open', mock_open()) as mock_file:
            with patch('pathlib.Path.mkdir'):
                with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
                    mock_datetime.now.return_value.strftime.return_value = "20240101_120000"

                    reporter.export_summary_to_text(report)

                    # Check that content was written using the file handle's write calls
                    handle = mock_file.return_value
                    written_calls = [call.args[0] for call in handle.write.call_args_list]
                    written_content = "".join(written_calls)
                    assert "FQDN ANALYSIS" in written_content
                    assert "Total FQDN rules: 100" in written_content
                    assert "Enabled rules: 80" in written_content
                    assert "Enablement rate: 80.00%" in written_content
                    assert "WebGroup rules: 30" in written_content

    def test_export_summary_to_text_with_validation_analysis(self):
        """Test text export with validation analysis included."""
        output_dir = Path("/tmp/test_output")
        reporter = TranslationReporter(output_dir)

        report = {
            "validation_analysis": {
                "validation_summary": {
                    "total_policies_analyzed": 100,
                    "total_issues_found": 15,
                    "validation_success_rate": 0.85
                },
                "issue_breakdown": {
                    "stateless_policy_issues": 5,
                    "duplicate_policies": 10
                }
            }
        }

        with patch('builtins.open', mock_open()) as mock_file:
            with patch('pathlib.Path.mkdir'):
                with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
                    mock_datetime.now.return_value.strftime.return_value = "20240101_120000"

                    reporter.export_summary_to_text(report)

                    # Check that content was written using the file handle's write calls
                    handle = mock_file.return_value
                    written_calls = [call.args[0] for call in handle.write.call_args_list]
                    written_content = "".join(written_calls)
                    assert "VALIDATION ANALYSIS" in written_content
                    assert "Total policies analyzed: 100" in written_content
                    assert "Issues found: 15" in written_content
                    assert "Success rate: 85.00%" in written_content
                    assert "Stateless Policy Issues: 5" in written_content

    def test_export_summary_to_text_with_recommendations(self):
        """Test text export with recommendations included."""
        output_dir = Path("/tmp/test_output")
        reporter = TranslationReporter(output_dir)

        report = {
            "recommendations": ["Recommendation 1", "Recommendation 2"]
        }

        with patch('builtins.open', mock_open()) as mock_file:
            with patch('pathlib.Path.mkdir'):
                with patch('src.analysis.translation_reporter.datetime') as mock_datetime:
                    mock_datetime.now.return_value.strftime.return_value = "20240101_120000"

                    reporter.export_summary_to_text(report)

                    # Check that content was written using the file handle's write calls
                    handle = mock_file.return_value
                    written_calls = [call.args[0] for call in handle.write.call_args_list]
                    written_content = "".join(written_calls)
                    assert "RECOMMENDATIONS" in written_content
                    assert "• Recommendation 1" in written_content
                    assert "• Recommendation 2" in written_content

    def test_calculate_completion_rate(self):
        """Test calculation of translation completion rate."""
        reporter = TranslationReporter(Path("/tmp"))
        
        # Test normal case
        stats = TranslationStats(
            input_counts={"fw_policy": 100, "fw_tag": 50},  # Total: 150
            output_counts={"smartgroups": 30, "webgroups": 20}  # Total: 50
        )
        
        rate = reporter._calculate_completion_rate(stats)
        assert rate == min(1.0, 50/150)  # 50/150 = 0.333...
        
        # Test zero input
        stats_zero_input = TranslationStats(
            input_counts={"fw_policy": 0, "fw_tag": 0},
            output_counts={"smartgroups": 10}
        )
        
        rate_zero = reporter._calculate_completion_rate(stats_zero_input)
        assert rate_zero == 0.0
        
        # Test higher output than input (capped at 1.0)
        stats_high_output = TranslationStats(
            input_counts={"fw_policy": 50},
            output_counts={"smartgroups": 100}
        )
        
        rate_high = reporter._calculate_completion_rate(stats_high_output)
        assert rate_high == 1.0

    def test_calculate_data_coverage(self):
        """Test calculation of data coverage."""
        reporter = TranslationReporter(Path("/tmp"))
        
        # Test normal case
        stats = TranslationStats(
            input_counts={"fw_policy": 100, "fw_tag": 50, "fqdn": 0},  # 2 types with data
            output_counts={"smartgroups": 30, "webgroups": 20, "policies": 0}  # 2 types with data
        )
        
        coverage = reporter._calculate_data_coverage(stats)
        assert coverage == 2/2  # 2 output types / 2 input types = 1.0
        
        # Test partial coverage
        stats_partial = TranslationStats(
            input_counts={"fw_policy": 100, "fw_tag": 50},  # 2 types with data
            output_counts={"smartgroups": 30, "webgroups": 0}  # 1 type with data
        )
        
        coverage_partial = reporter._calculate_data_coverage(stats_partial)
        assert coverage_partial == 1/2  # 1 output type / 2 input types = 0.5
        
        # Test zero input types
        stats_zero_input = TranslationStats(
            input_counts={"fw_policy": 0, "fw_tag": 0},  # 0 types with data
            output_counts={"smartgroups": 10}
        )
        
        coverage_zero = reporter._calculate_data_coverage(stats_zero_input)
        assert coverage_zero == 0.0

    def test_generate_recommendations_fqdn_based(self):
        """Test recommendation generation based on FQDN analysis."""
        reporter = TranslationReporter(Path("/tmp"))
        
        report_low_compatibility = {
            "fqdn_analysis": {
                "domain_compatibility": {
                    "compatibility_rate": 0.8,  # < 0.95
                    "dcf_incompatible_domains": 10
                },
                "dcf_translation_breakdown": {
                    "webgroup_percentage": 30  # < 50
                }
            }
        }
        
        recommendations = reporter._generate_recommendations(report_low_compatibility)
        
        assert len(recommendations) == 2
        assert any("10 domains that are incompatible" in rec for rec in recommendations)
        assert any("consolidating more FQDN rules to use WebGroups" in rec for rec in recommendations)

    def test_generate_recommendations_validation_based(self):
        """Test recommendation generation based on validation analysis."""
        reporter = TranslationReporter(Path("/tmp"))
        
        report_validation_issues = {
            "validation_analysis": {
                "issue_breakdown": {
                    "stateless_policy_issues": 5,
                    "duplicate_policies": 8,
                    "unused_firewall_tags": 3
                }
            }
        }
        
        recommendations = reporter._generate_recommendations(report_validation_issues)
        
        assert len(recommendations) == 3
        assert any("stateless policy issues" in rec for rec in recommendations)
        assert any("duplicate policies" in rec for rec in recommendations)
        assert any("unused firewall tags" in rec for rec in recommendations)

    def test_generate_recommendations_success_metrics_based(self):
        """Test recommendation generation based on success metrics."""
        reporter = TranslationReporter(Path("/tmp"))
        
        report_low_completion = {
            "success_metrics": {
                "translation_completion_rate": 0.75  # < 0.9
            }
        }
        
        recommendations = reporter._generate_recommendations(report_low_completion)
        
        assert len(recommendations) == 1
        assert "translation process" in recommendations[0]

    def test_generate_recommendations_no_issues(self):
        """Test recommendation generation when no issues are found."""
        reporter = TranslationReporter(Path("/tmp"))
        
        report_good = {
            "fqdn_analysis": {
                "domain_compatibility": {"compatibility_rate": 1.0},
                "dcf_translation_breakdown": {"webgroup_percentage": 70}
            },
            "validation_analysis": {
                "issue_breakdown": {
                    "stateless_policy_issues": 0,
                    "duplicate_policies": 0,
                    "unused_firewall_tags": 0
                }
            },
            "success_metrics": {
                "translation_completion_rate": 0.95
            }
        }
        
        recommendations = reporter._generate_recommendations(report_good)
        
        assert len(recommendations) == 1
        assert "successfully with no major issues" in recommendations[0]

    def test_generate_recommendations_empty_report(self):
        """Test recommendation generation with empty report."""
        reporter = TranslationReporter(Path("/tmp"))
        
        empty_report = {}
        
        recommendations = reporter._generate_recommendations(empty_report)
        
        assert len(recommendations) == 1
        assert "successfully with no major issues" in recommendations[0]
