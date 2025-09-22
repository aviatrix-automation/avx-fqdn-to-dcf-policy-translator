"""
FQDN analysis module for analyzing domain categorization and compatibility.

This module provides classes for analyzing FQDN rules, categorizing domains
for DCF compatibility, and generating detailed reports on FQDN processing.
"""

import logging
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pandas as pd

sys.path.append(str(Path(__file__).parent.parent))
from domain.constants import DCF_SNI_DOMAIN_PATTERN


@dataclass
class FQDNAnalysisResult:
    """Result of FQDN analysis containing statistics and categorization data."""

    total_rules: int
    enabled_rules: int
    disabled_rules: int
    webgroup_rules: int
    hostname_rules: int
    unsupported_rules: int
    unique_domains: int
    dcf_compatible_domains: int
    dcf_incompatible_domains: int
    protocol_breakdown: Dict[str, int]
    port_breakdown: Dict[str, int]
    mode_breakdown: Dict[str, int]
    gateway_breakdown: Dict[str, int]


class FQDNCategorizer:
    """Categorizes FQDN rules by type, protocol, ports, and compatibility."""

    def __init__(self, default_web_ports: Optional[Set[str]] = None):
        """
        Initialize the FQDN categorizer.

        Args:
            default_web_ports: Set of default web ports (80, 443 if None)
        """
        self.default_web_ports = default_web_ports or {"80", "443"}
        self.logger = logging.getLogger(__name__)

    def categorize_by_protocol_port(
        self, fqdn_rules_df: pd.DataFrame, fqdn_df: pd.DataFrame = None
    ) -> Dict[str, pd.DataFrame]:
        """
        Categorize FQDN rules by protocol and port for DCF component assignment.

        Args:
            fqdn_rules_df: DataFrame containing FQDN rules
            fqdn_df: Optional DataFrame containing FQDN definitions with enabled status

        Returns:
            Dictionary with categorized rule DataFrames
        """
        if fqdn_rules_df.empty:
            return {
                "webgroup_rules": pd.DataFrame(),
                "hostname_rules": pd.DataFrame(),
                "unsupported_rules": pd.DataFrame(),
            }

        # If fqdn_df is provided, filter by enabled rules only
        if fqdn_df is not None and not fqdn_df.empty:
            # Get enabled FQDN tags
            enabled_tags = set(fqdn_df[fqdn_df["fqdn_enabled"]]["fqdn_tag"].tolist())
            # Filter rules to only include enabled tags
            enabled_rules = fqdn_rules_df[fqdn_rules_df["fqdn_tag_name"].isin(enabled_tags)].copy()
        else:
            # If no fqdn_df provided, use all rules
            enabled_rules = fqdn_rules_df.copy()

        # WebGroup rules: HTTP/HTTPS on standard web ports
        webgroup_mask = (enabled_rules["protocol"].str.lower().isin(["tcp", "http", "https"])) & (
            enabled_rules["port"].isin(self.default_web_ports)
        )
        webgroup_rules = enabled_rules[webgroup_mask].copy()

        # Hostname rules: All other enabled rules
        hostname_rules = enabled_rules[~webgroup_mask].copy()

        # Convert protocol "all" to "ANY" for DCF compatibility
        hostname_rules.loc[hostname_rules["protocol"] == "all", "protocol"] = "ANY"

        # Handle blank ports by setting to "ALL" for hostname SmartGroups
        hostname_rules.loc[hostname_rules["port"] == "", "port"] = "ALL"

        # No more truly unsupported rules in current implementation
        unsupported_rules = pd.DataFrame()

        self.logger.info(
            f"FQDN rules categorized: {len(webgroup_rules)} webgroup rules, "
            f"{len(hostname_rules)} hostname rules, {len(unsupported_rules)} unsupported rules"
        )

        return {
            "webgroup_rules": webgroup_rules,
            "hostname_rules": hostname_rules,
            "unsupported_rules": unsupported_rules,
        }

    def categorize_by_mode(self, fqdn_rules_df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
        """
        Categorize FQDN rules by mode (white/black).

        Args:
            fqdn_rules_df: DataFrame containing FQDN rules

        Returns:
            Dictionary with rules categorized by mode
        """
        categories = {}
        for mode in fqdn_rules_df["fqdn_mode"].unique():
            categories[f"{mode}_rules"] = fqdn_rules_df[fqdn_rules_df["fqdn_mode"] == mode].copy()

        return categories

    def categorize_by_gateway(self, fqdn_rules_df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
        """
        Categorize FQDN rules by gateway.

        Args:
            fqdn_rules_df: DataFrame containing FQDN rules

        Returns:
            Dictionary with rules categorized by gateway
        """
        categories: Dict[str, Any] = {}

        # Extract gateway name from gw_filter_tag_list if available
        if "gw_filter_tag_list" in fqdn_rules_df.columns:
            for _idx, row in fqdn_rules_df.iterrows():
                gw_filter = row.get("gw_filter_tag_list", {})
                if isinstance(gw_filter, dict) and "gw_name" in gw_filter:
                    gw_name = gw_filter["gw_name"]
                    if gw_name not in categories:
                        categories[gw_name] = []
                    categories[gw_name].append(row)

        # Convert lists to DataFrames
        for gw_name, rules in categories.items():
            categories[gw_name] = pd.DataFrame(rules)

        return categories


class DomainCompatibilityAnalyzer:
    """Analyzes domain compatibility with DCF 8.0 SNI requirements."""

    def __init__(self, skip_incompatible_domain_filtering: bool = False) -> None:
        """
        Initialize the domain compatibility analyzer.
        
        Args:
            skip_incompatible_domain_filtering: If True, skip filtering of incompatible domains
                                               (for controller version 8.1+)
        """
        self.logger = logging.getLogger(__name__)
        self.sni_pattern = DCF_SNI_DOMAIN_PATTERN
        self.skip_incompatible_domain_filtering = skip_incompatible_domain_filtering

    def analyze_domain_compatibility(self, domains: List[str]) -> Dict[str, Any]:
        """
        Analyze a list of domains for DCF 8.0 SNI compatibility.

        Args:
            domains: List of domain names to analyze

        Returns:
            Dictionary containing compatibility analysis results
        """
        import re

        total_domains = len(domains)
        valid_domains = []
        invalid_domains = []
        invalid_reasons = defaultdict(list)

        for domain in domains:
            # If we're skipping incompatible domain filtering (8.1+), treat all domains as valid
            if self.skip_incompatible_domain_filtering:
                valid_domains.append(domain)
            elif re.match(self.sni_pattern, domain):
                valid_domains.append(domain)
            else:
                invalid_domains.append(domain)
                # Analyze why domain is invalid
                if len(domain) == 0:
                    invalid_reasons["empty"].append(domain)
                elif not re.match(r"^[a-zA-Z0-9*._-]+$", domain):
                    invalid_reasons["invalid_characters"].append(domain)
                elif domain.startswith("*.*."):
                    invalid_reasons["multiple_wildcards"].append(domain)
                elif "*" in domain and not domain.startswith("*."):
                    invalid_reasons["invalid_wildcard_position"].append(domain)
                else:
                    invalid_reasons["other"].append(domain)

        return {
            "total_domains": total_domains,
            "valid_domains": valid_domains,
            "invalid_domains": invalid_domains,
            "valid_count": len(valid_domains),
            "invalid_count": len(invalid_domains),
            "compatibility_rate": len(valid_domains) / total_domains if total_domains > 0 else 0,
            "invalid_reasons": dict(invalid_reasons),
        }

    def analyze_webgroup_domains(self, webgroups_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze domain compatibility for all WebGroups.

        Args:
            webgroups_df: DataFrame containing WebGroup definitions

        Returns:
            Dictionary containing per-webgroup compatibility analysis
        """
        webgroup_analysis = {}

        for _idx, row in webgroups_df.iterrows():
            webgroup_name = row["name"]
            domains = row.get("domains", [])

            if domains:
                analysis = self.analyze_domain_compatibility(domains)
                webgroup_analysis[webgroup_name] = analysis

                if analysis["invalid_count"] > 0:
                    # Only log warnings about incompatible domains if we're actually filtering them
                    if not self.skip_incompatible_domain_filtering:
                        self.logger.warning(
                            f"WebGroup '{webgroup_name}' has {analysis['invalid_count']} "
                            f"DCF 8.0 incompatible domains out of {analysis['total_domains']}"
                        )
                    else:
                        self.logger.info(
                            f"WebGroup '{webgroup_name}' has {analysis['invalid_count']} "
                            f"domains that would be incompatible with DCF 8.0 but are included "
                            f"due to controller version 8.1+ support"
                        )

        return webgroup_analysis


class FQDNAnalyzer:
    """Main FQDN analyzer that orchestrates various analysis operations."""

    def __init__(self, default_web_ports: Optional[Set[str]] = None, skip_incompatible_domain_filtering: bool = False):
        """
        Initialize the FQDN analyzer.

        Args:
            default_web_ports: Set of default web ports (80, 443 if None)
            skip_incompatible_domain_filtering: If True, skip filtering of incompatible domains
                                               (for controller version 8.1+)
        """
        self.categorizer = FQDNCategorizer(default_web_ports)
        self.domain_analyzer = DomainCompatibilityAnalyzer(skip_incompatible_domain_filtering)
        self.logger = logging.getLogger(__name__)

    def analyze_fqdn_rules(
        self, fqdn_tag_rule_df: pd.DataFrame, fqdn_df: pd.DataFrame
    ) -> FQDNAnalysisResult:
        """
        Perform comprehensive analysis of FQDN rules.

        Args:
            fqdn_tag_rule_df: DataFrame containing FQDN tag rules
            fqdn_df: DataFrame containing FQDN definitions

        Returns:
            FQDNAnalysisResult containing detailed analysis
        """
        # Basic statistics
        total_rules = len(fqdn_tag_rule_df)
        # fqdn_enabled is in fqdn_df, not fqdn_tag_rule_df
        enabled_rules = len(fqdn_df[fqdn_df["fqdn_enabled"]]) if not fqdn_df.empty else 0
        disabled_rules = len(fqdn_df[~fqdn_df["fqdn_enabled"]]) if not fqdn_df.empty else 0

        # Categorize rules
        categories = self.categorizer.categorize_by_protocol_port(fqdn_tag_rule_df, fqdn_df)
        webgroup_rules = len(categories["webgroup_rules"])
        hostname_rules = len(categories["hostname_rules"])
        unsupported_rules = len(categories["unsupported_rules"])

        # Domain analysis
        unique_domains = fqdn_tag_rule_df["fqdn"].nunique() if not fqdn_tag_rule_df.empty else 0
        all_domains = fqdn_tag_rule_df["fqdn"].tolist() if not fqdn_tag_rule_df.empty else []
        domain_compat = self.domain_analyzer.analyze_domain_compatibility(all_domains)

        # Breakdown by various fields
        protocol_breakdown = dict(fqdn_tag_rule_df["protocol"].value_counts())
        port_breakdown = dict(fqdn_tag_rule_df["port"].value_counts())
        mode_breakdown = dict(fqdn_df["fqdn_mode"].value_counts()) if not fqdn_df.empty else {}

        # Gateway breakdown
        gateway_breakdown: Dict[str, int] = {}
        if not fqdn_df.empty and "gw_filter_tag_list" in fqdn_df.columns:
            for _idx, row in fqdn_df.iterrows():
                gw_filter = row.get("gw_filter_tag_list", {})
                if isinstance(gw_filter, dict) and "gw_name" in gw_filter:
                    gw_name = gw_filter["gw_name"]
                    gateway_breakdown[gw_name] = gateway_breakdown.get(gw_name, 0) + 1

        return FQDNAnalysisResult(
            total_rules=total_rules,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            webgroup_rules=webgroup_rules,
            hostname_rules=hostname_rules,
            unsupported_rules=unsupported_rules,
            unique_domains=unique_domains,
            dcf_compatible_domains=domain_compat["valid_count"],
            dcf_incompatible_domains=domain_compat["invalid_count"],
            protocol_breakdown=protocol_breakdown,
            port_breakdown=port_breakdown,
            mode_breakdown=mode_breakdown,
            gateway_breakdown=gateway_breakdown,
        )

    def generate_analysis_report(self, analysis_result: FQDNAnalysisResult) -> Dict[str, Any]:
        """
        Generate a detailed analysis report.

        Args:
            analysis_result: Result of FQDN analysis

        Returns:
            Dictionary containing formatted analysis report
        """
        report = {
            "summary": {
                "total_fqdn_rules": analysis_result.total_rules,
                "enabled_rules": analysis_result.enabled_rules,
                "disabled_rules": analysis_result.disabled_rules,
                "enablement_rate": analysis_result.enabled_rules / analysis_result.total_rules
                if analysis_result.total_rules > 0
                else 0,
            },
            "dcf_translation": {
                "webgroup_rules": analysis_result.webgroup_rules,
                "hostname_smartgroup_rules": analysis_result.hostname_rules,
                "unsupported_rules": analysis_result.unsupported_rules,
                "webgroup_rate": analysis_result.webgroup_rules / analysis_result.enabled_rules
                if analysis_result.enabled_rules > 0
                else 0,
                "hostname_rate": analysis_result.hostname_rules / analysis_result.enabled_rules
                if analysis_result.enabled_rules > 0
                else 0,
            },
            "domain_analysis": {
                "unique_domains": analysis_result.unique_domains,
                "dcf_compatible_domains": analysis_result.dcf_compatible_domains,
                "dcf_incompatible_domains": analysis_result.dcf_incompatible_domains,
                "compatibility_rate": analysis_result.dcf_compatible_domains
                / analysis_result.unique_domains
                if analysis_result.unique_domains > 0
                else 0,
            },
            "breakdowns": {
                "by_protocol": analysis_result.protocol_breakdown,
                "by_port": analysis_result.port_breakdown,
                "by_mode": analysis_result.mode_breakdown,
                "by_gateway": analysis_result.gateway_breakdown,
            },
        }

        return report

    def log_analysis_summary(self, analysis_result: FQDNAnalysisResult) -> None:
        """
        Log a summary of the analysis results.

        Args:
            analysis_result: Result of FQDN analysis
        """
        self.logger.info("FQDN Analysis Summary:")
        self.logger.info(f"  Total FQDN rules: {analysis_result.total_rules}")
        self.logger.info(f"  Enabled rules: {analysis_result.enabled_rules}")
        self.logger.info(f"  Rules for WebGroups: {analysis_result.webgroup_rules}")
        self.logger.info(f"  Rules for hostname SmartGroups: {analysis_result.hostname_rules}")
        self.logger.info(f"  Unsupported rules: {analysis_result.unsupported_rules}")
        self.logger.info(f"  Unique domains: {analysis_result.unique_domains}")
        self.logger.info(f"  DCF 8.0 compatible domains: {analysis_result.dcf_compatible_domains}")
        self.logger.info(
            f"  DCF 8.0 incompatible domains: {analysis_result.dcf_incompatible_domains}"
        )

        if analysis_result.dcf_incompatible_domains > 0:
            self.logger.warning(
                f"Found {analysis_result.dcf_incompatible_domains} domains incompatible "
                f"with DCF 8.0 SNI requirements"
            )
