"""
Translation reporting module for generating comprehensive analysis reports.

This module provides classes for generating detailed reports on translation
statistics, issues, and overall translation health.
"""

import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.append(str(Path(__file__).parent.parent))
from analysis.fqdn_analysis import FQDNAnalysisResult
from analysis.policy_validators import ValidationResult


@dataclass
class TranslationStats:
    """Statistics about the overall translation process."""

    input_counts: Dict[str, int]
    output_counts: Dict[str, int]
    processing_time: Optional[float] = None
    timestamp: Optional[str] = None


class TranslationReporter:
    """Generates comprehensive reports on translation results and analysis."""

    def __init__(self, output_dir: Path):
        """
        Initialize the translation reporter.

        Args:
            output_dir: Directory where reports will be saved
        """
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger(__name__)

    def generate_summary_statistics(self, data: Dict[str, Any]) -> TranslationStats:
        """
        Generate summary statistics from translation data.

        Args:
            data: Dictionary containing all translation data

        Returns:
            TranslationStats object with summary information
        """
        # Count input data
        input_counts = {}
        input_keys = ["fw_policy_df", "fw_tag_df", "fqdn_df", "fqdn_tag_rule_df"]
        for key in input_keys:
            if key in data and hasattr(data[key], "__len__"):
                input_counts[key.replace("_df", "")] = len(data[key])
            else:
                input_counts[key.replace("_df", "")] = 0

        # Count output data
        output_counts = {}
        output_keys = ["smartgroups_df", "webgroups_df", "hostname_policies_df", "full_policy_list"]
        for key in output_keys:
            if key in data and hasattr(data[key], "__len__"):
                output_counts[key.replace("_df", "").replace("_list", "")] = len(data[key])
            else:
                output_counts[key.replace("_df", "").replace("_list", "")] = 0

        return TranslationStats(
            input_counts=input_counts,
            output_counts=output_counts,
            timestamp=datetime.now().isoformat(),
        )

    def generate_fqdn_report(self, fqdn_analysis: FQDNAnalysisResult) -> Dict[str, Any]:
        """
        Generate a detailed FQDN analysis report.

        Args:
            fqdn_analysis: Result of FQDN analysis

        Returns:
            Dictionary containing formatted FQDN report
        """
        report = {
            "fqdn_summary": {
                "total_fqdn_rules": fqdn_analysis.total_rules,
                "enabled_rules": fqdn_analysis.enabled_rules,
                "disabled_rules": fqdn_analysis.disabled_rules,
                "enablement_rate": fqdn_analysis.enabled_rules / max(fqdn_analysis.total_rules, 1),
            },
            "dcf_translation_breakdown": {
                "webgroup_rules": fqdn_analysis.webgroup_rules,
                "hostname_smartgroup_rules": fqdn_analysis.hostname_rules,
                "unsupported_rules": fqdn_analysis.unsupported_rules,
                "webgroup_percentage": fqdn_analysis.webgroup_rules
                / max(fqdn_analysis.enabled_rules, 1)
                * 100,
                "hostname_percentage": fqdn_analysis.hostname_rules
                / max(fqdn_analysis.enabled_rules, 1)
                * 100,
            },
            "domain_compatibility": {
                "unique_domains": fqdn_analysis.unique_domains,
                "dcf_compatible_domains": fqdn_analysis.dcf_compatible_domains,
                "dcf_incompatible_domains": fqdn_analysis.dcf_incompatible_domains,
                "compatibility_rate": fqdn_analysis.dcf_compatible_domains
                / max(fqdn_analysis.unique_domains, 1),
            },
            "breakdown_analysis": {
                "protocols": fqdn_analysis.protocol_breakdown,
                "ports": fqdn_analysis.port_breakdown,
                "modes": fqdn_analysis.mode_breakdown,
                "gateways": fqdn_analysis.gateway_breakdown,
            },
        }

        return report

    def generate_validation_report(self, validation_result: ValidationResult) -> Dict[str, Any]:
        """
        Generate a detailed validation report.

        Args:
            validation_result: Result of policy validation

        Returns:
            Dictionary containing formatted validation report
        """
        report = {
            "validation_summary": {
                "total_policies_analyzed": validation_result.total_policies,
                "total_issues_found": validation_result.issues_found,
                "validation_success_rate": 1
                - (validation_result.issues_found / max(validation_result.total_policies, 1)),
            },
            "issue_breakdown": {
                "stateless_policy_issues": validation_result.stateless_issues,
                "unused_firewall_tags": len(validation_result.unused_tags),
                "single_cidr_tags_found": len(validation_result.single_cidr_tags),
                "duplicate_policies": validation_result.duplicate_policies,
                "validation_warnings": len(validation_result.validation_warnings),
                "validation_errors": len(validation_result.validation_errors),
            },
            "detailed_findings": {
                "unused_tags": list(validation_result.unused_tags),
                "single_cidr_mappings": validation_result.single_cidr_tags,
                "warnings": validation_result.validation_warnings,
                "errors": validation_result.validation_errors,
            },
        }

        return report

    def generate_comprehensive_report(
        self,
        data: Dict[str, Any],
        fqdn_analysis: Optional[FQDNAnalysisResult] = None,
        validation_result: Optional[ValidationResult] = None,
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive translation report.

        Args:
            data: Dictionary containing all translation data
            fqdn_analysis: Optional FQDN analysis results
            validation_result: Optional validation results

        Returns:
            Dictionary containing complete translation report
        """
        # Generate base statistics
        stats = self.generate_summary_statistics(data)

        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_version": "1.0",
                "translator_type": "legacy-to-dcf",
            },
            "translation_summary": asdict(stats),
            "success_metrics": {
                "translation_completion_rate": self._calculate_completion_rate(stats),
                "data_coverage": self._calculate_data_coverage(stats),
            },
        }

        # Add FQDN analysis if available
        if fqdn_analysis:
            report["fqdn_analysis"] = self.generate_fqdn_report(fqdn_analysis)

        # Add validation results if available
        if validation_result:
            report["validation_analysis"] = self.generate_validation_report(validation_result)

        # Generate recommendations
        recommendations = self._generate_recommendations(report)
        report["recommendations"] = {"items": recommendations}

        return report

    def export_report_to_json(self, report: Dict[str, Any], filename: Optional[str] = None) -> Path:
        """
        Export translation report to JSON file.

        Args:
            report: Report dictionary to export
            filename: Optional custom filename

        Returns:
            Path to the exported report file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"translation_report_{timestamp}.json"

        output_file = self.output_dir / filename
        self.output_dir.mkdir(parents=True, exist_ok=True)

        try:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2, default=str)

            self.logger.info(f"Exported comprehensive translation report to {output_file}")
            return output_file

        except Exception as e:
            self.logger.error(f"Failed to export translation report: {e}")
            raise

    def export_summary_to_text(
        self, report: Dict[str, Any], filename: Optional[str] = None
    ) -> Path:
        """
        Export a human-readable summary of the translation report.

        Args:
            report: Report dictionary to summarize
            filename: Optional custom filename

        Returns:
            Path to the exported summary file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"translation_summary_{timestamp}.txt"

        output_file = self.output_dir / filename
        self.output_dir.mkdir(parents=True, exist_ok=True)

        try:
            with open(output_file, "w") as f:
                f.write("LEGACY TO DCF POLICY TRANSLATION REPORT\\n")
                f.write("=" * 50 + "\\n\\n")

                # Report metadata
                if "report_metadata" in report:
                    f.write(
                        f"Generated: {report['report_metadata'].get('generated_at', 'Unknown')}\\n"
                    )
                    version = report["report_metadata"].get("report_version", "Unknown")
                    f.write(f"Version: {version}\\n\\n")

                # Translation summary
                if "translation_summary" in report:
                    f.write("TRANSLATION SUMMARY\\n")
                    f.write("-" * 20 + "\\n")

                    input_counts = report["translation_summary"].get("input_counts", {})
                    output_counts = report["translation_summary"].get("output_counts", {})

                    f.write("Input Data:\\n")
                    for key, count in input_counts.items():
                        f.write(f"  {key}: {count}\\n")

                    f.write("\\nOutput Data:\\n")
                    for key, count in output_counts.items():
                        f.write(f"  {key}: {count}\\n")
                    f.write("\\n")

                # FQDN analysis
                if "fqdn_analysis" in report:
                    f.write("FQDN ANALYSIS\\n")
                    f.write("-" * 15 + "\\n")

                    fqdn_summary = report["fqdn_analysis"].get("fqdn_summary", {})
                    f.write(f"Total FQDN rules: {fqdn_summary.get('total_fqdn_rules', 0)}\\n")
                    f.write(f"Enabled rules: {fqdn_summary.get('enabled_rules', 0)}\\n")
                    f.write(f"Enablement rate: {fqdn_summary.get('enablement_rate', 0):.2%}\\n")

                    dcf_breakdown = report["fqdn_analysis"].get("dcf_translation_breakdown", {})
                    f.write("\\nDCF Translation:\\n")
                    f.write(f"  WebGroup rules: {dcf_breakdown.get('webgroup_rules', 0)}\\n")
                    hostname_sg_rules = dcf_breakdown.get("hostname_smartgroup_rules", 0)
                    f.write(f"  Hostname SmartGroup rules: {hostname_sg_rules}\\n")
                    f.write(f"  Unsupported rules: {dcf_breakdown.get('unsupported_rules', 0)}\\n")
                    f.write("\\n")

                # Validation analysis
                if "validation_analysis" in report:
                    f.write("VALIDATION ANALYSIS\\n")
                    f.write("-" * 20 + "\\n")

                    validation_summary = report["validation_analysis"].get("validation_summary", {})
                    total_policies = validation_summary.get("total_policies_analyzed", 0)
                    f.write(f"Total policies analyzed: {total_policies}\\n")
                    f.write(f"Issues found: {validation_summary.get('total_issues_found', 0)}\\n")
                    success_rate = validation_summary.get("validation_success_rate", 0)
                    f.write(f"Success rate: {success_rate:.2%}\\n")

                    issue_breakdown = report["validation_analysis"].get("issue_breakdown", {})
                    f.write("\\nIssue Breakdown:\\n")
                    for issue_type, count in issue_breakdown.items():
                        f.write(f"  {issue_type.replace('_', ' ').title()}: {count}\\n")
                    f.write("\\n")

                # Recommendations
                if "recommendations" in report:
                    f.write("RECOMMENDATIONS\\n")
                    f.write("-" * 15 + "\\n")
                    for recommendation in report["recommendations"]:
                        f.write(f"• {recommendation}\\n")

            self.logger.info(f"Exported translation summary to {output_file}")
            return output_file

        except Exception as e:
            self.logger.error(f"Failed to export summary report: {e}")
            raise

    def _calculate_completion_rate(self, stats: TranslationStats) -> float:
        """Calculate overall translation completion rate."""
        total_input = sum(stats.input_counts.values())
        total_output = sum(stats.output_counts.values())

        if total_input == 0:
            return 0.0

        # This is a simplified calculation - in reality, the relationship
        # between input and output counts is more complex
        return min(1.0, total_output / total_input)

    def _calculate_data_coverage(self, stats: TranslationStats) -> float:
        """Calculate what percentage of input data was processed."""
        # Simplified calculation based on whether we have output for each input type
        input_types = len([v for v in stats.input_counts.values() if v > 0])
        output_types = len([v for v in stats.output_counts.values() if v > 0])

        if input_types == 0:
            return 0.0

        return output_types / input_types

    def _generate_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on report analysis."""
        recommendations = []

        # FQDN-related recommendations
        if "fqdn_analysis" in report:
            fqdn_analysis = report["fqdn_analysis"]

            # Domain compatibility recommendations
            domain_compat = fqdn_analysis.get("domain_compatibility", {})
            compat_rate = domain_compat.get("compatibility_rate", 1.0)

            if compat_rate < 0.95:
                recommendations.append(
                    f"Consider reviewing {domain_compat.get('dcf_incompatible_domains', 0)} "
                    "domains that are incompatible with DCF 8.0 SNI requirements"
                )

            # Rule distribution recommendations
            dcf_breakdown = fqdn_analysis.get("dcf_translation_breakdown", {})
            webgroup_pct = dcf_breakdown.get("webgroup_percentage", 0)

            if webgroup_pct < 50:
                recommendations.append(
                    "Consider consolidating more FQDN rules to use WebGroups for better performance"
                )

        # Validation-related recommendations
        if "validation_analysis" in report:
            validation = report["validation_analysis"]

            issue_breakdown = validation.get("issue_breakdown", {})

            if issue_breakdown.get("stateless_policy_issues", 0) > 0:
                recommendations.append(
                    "Review stateless policy issues that may cause bi-directional drops"
                )

            if issue_breakdown.get("duplicate_policies", 0) > 0:
                recommendations.append(
                    "Clean up duplicate policies to reduce configuration complexity"
                )

            if issue_breakdown.get("unused_firewall_tags", 0) > 0:
                recommendations.append("Remove unused firewall tags to simplify configuration")

        # Success metrics recommendations
        if "success_metrics" in report:
            success_metrics = report["success_metrics"]
            completion_rate = success_metrics.get("translation_completion_rate", 1.0)

            if completion_rate < 0.9:
                recommendations.append(
                    "Review translation process to ensure all policies are properly converted"
                )

        if not recommendations:
            recommendations.append(
                "Translation completed successfully with no major issues identified"
            )

        return recommendations
