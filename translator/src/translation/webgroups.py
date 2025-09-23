"""
WebGroup creation and management for the legacy-to-DCF policy translator.

This module handles the translation of FQDN tags to WebGroups for HTTP/HTTPS traffic
optimization. WebGroups are used for standard web ports (80, 443) to provide optimal
performance for web traffic filtering.
"""

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

import pandas as pd

from config import TranslationConfig
from config.defaults import DCF_CONSTRAINTS
from data.processors import DataCleaner
from domain.constants import FQDN_MODE_MAPPINGS
from utils.data_processing import normalize_protocol
from utils.cidr_validator import CIDRValidator
from .fqdn_handlers import FQDNValidator
from .unsupported_fqdn_tracker import UnsupportedFQDNTracker
from .unsupported_cidr_tracker import UnsupportedCIDRTracker


class WebGroupBuilder:
    """Handles the creation and management of WebGroups from FQDN tag rules."""

    def __init__(self, unsupported_fqdn_tracker: Optional[UnsupportedFQDNTracker] = None, unsupported_cidr_tracker: Optional[UnsupportedCIDRTracker] = None, skip_incompatible_domain_filtering: bool = False) -> None:
        self.all_invalid_domains: List[Dict[str, str]] = []
        self.cleaner = DataCleaner(TranslationConfig())
        self.unsupported_fqdn_tracker = unsupported_fqdn_tracker or UnsupportedFQDNTracker()
        self.unsupported_cidr_tracker = unsupported_cidr_tracker or UnsupportedCIDRTracker()
        self.skip_incompatible_domain_filtering = skip_incompatible_domain_filtering

    def create_webgroup_name(self, row: pd.Series) -> str:
        """
        Create a standardized WebGroup name from FQDN tag rule data.

        Args:
            row: DataFrame row containing fqdn_tag_name, protocol, port, fqdn_mode

        Returns:
            Formatted WebGroup name: {tag_name}_{mode}_{protocol}_{port}
        """
        mode_suffix = FQDN_MODE_MAPPINGS.get(row["fqdn_mode"], row["fqdn_mode"])
        return "{}_{}_{}_{}".format(row["fqdn_tag_name"], mode_suffix, row["protocol"], row["port"])

    def filter_and_create_selector(self, row: pd.Series) -> Dict[str, Any]:
        """
        Filter domains for DCF 8.0 compatibility and create WebGroup selector.

        Args:
            row: DataFrame row containing name, fqdn (list of domains), fqdn_tag_name, protocol, port

        Returns:
            WebGroup selector dictionary with filtered domains
        """
        webgroup_name = row["name"]
        fqdn_tag_name = row["fqdn_tag_name"]
        protocol = normalize_protocol(row["protocol"])
        port = str(row["port"])
        original_domains = row["fqdn"]
        
        # First filter out CIDR and IP address entries
        # Filter out CIDR entries that aren't valid for SNI filters (IP addresses are valid)
        domains_without_cidr, cidr_entries = CIDRValidator.filter_cidr_notation(
            original_domains, f"WebGroup {webgroup_name}"
        )
        
        # Track CIDR entries that were filtered out
        if cidr_entries:
            logging.warning(f"WebGroup '{webgroup_name}' had {len(cidr_entries)} CIDR entries filtered: {cidr_entries}")
            for cidr_entry in cidr_entries:
                self.unsupported_cidr_tracker.add_cidr_entry(
                    fqdn_tag_name=fqdn_tag_name,
                    webgroup_name=webgroup_name,
                    cidr_entry=cidr_entry,
                    port=port,
                    protocol=protocol,
                    entry_type="CIDR",
                    reason="CIDR notation not supported in SNI filters"
                )
        
        # Then filter remaining domains for DCF 8.0 compatibility
        valid_domains, invalid_domains = FQDNValidator.filter_domains_for_dcf_compatibility(
            domains_without_cidr, webgroup_name, self.skip_incompatible_domain_filtering
        )

        # Log if all domains were filtered out
        if len(original_domains) > 0 and len(valid_domains) == 0:
            cidr_count = len(cidr_entries)
            invalid_count = len(invalid_domains)
            logging.warning(f"WebGroup '{webgroup_name}' will be empty - all {len(original_domains)} entries were filtered ({cidr_count} CIDR, {invalid_count} DCF-incompatible)")

        if invalid_domains:
            # Store invalid domains for reporting (legacy format)
            self.all_invalid_domains.extend(
                [{"webgroup": webgroup_name, "domain": domain} for domain in invalid_domains]
            )
            
            # Add detailed records to the tracker
            for domain in invalid_domains:
                self.unsupported_fqdn_tracker.add_invalid_domain(
                    fqdn_tag_name=fqdn_tag_name,
                    webgroup_name=webgroup_name,
                    domain=domain,
                    port=port,
                    protocol=protocol,
                    reason="DCF 8.0 incompatible SNI domain pattern"
                )

        return self._translate_fqdn_to_selector(valid_domains)

    def _translate_fqdn_to_selector(self, fqdn_list: List[str]) -> Dict[str, Any]:
        """
        Convert FQDN list to WebGroup selector format.

        Args:
            fqdn_list: List of FQDN strings

        Returns:
            WebGroup selector dictionary
        """
        match_expressions = []
        for fqdn in fqdn_list:
            match_expressions.append({"snifilter": fqdn.strip()})
        return {"match_expressions": match_expressions}

    def build_webgroup_dataframe(self, fqdn_tag_rule_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build WebGroups DataFrame from FQDN tag rules.

        Args:
            fqdn_tag_rule_df: DataFrame with FQDN tag rules for web traffic

        Returns:
            DataFrame with WebGroup configurations (name, selector)
        """
        if len(fqdn_tag_rule_df) == 0:
            logging.info("No FQDN tag rules provided for WebGroup creation")
            return pd.DataFrame(columns=["name", "selector"])

        # Group FQDNs by webgroup criteria (tag, protocol, port, mode)
        grouped_df = (
            fqdn_tag_rule_df.groupby(["fqdn_tag_name", "protocol", "port", "fqdn_mode"])["fqdn"]
            .apply(list)
            .reset_index()
        )

        # Generate WebGroup names
        grouped_df["name"] = grouped_df.apply(self.create_webgroup_name, axis=1)

        # Filter domains for DCF 8.0 compatibility and create selectors
        grouped_df["selector"] = grouped_df.apply(self.filter_and_create_selector, axis=1)

        # Filter out WebGroups with empty match_expressions (all domains were filtered)
        initial_count = len(grouped_df)
        # Check if match_expressions array is empty
        valid_mask = grouped_df["selector"].apply(
            lambda x: len(x.get("match_expressions", [])) > 0
        )
        grouped_df = grouped_df[valid_mask]
        filtered_count = initial_count - len(grouped_df)
        
        if filtered_count > 0:
            logging.warning(
                f"Filtered out {filtered_count} WebGroups with no valid DCF-compatible domains"
            )

        # Clean WebGroup names for DCF compatibility
        grouped_df = self.cleaner.remove_invalid_name_chars(grouped_df, "name")

        # Log summary of filtered domains if any
        self._log_filtered_domains()

        return grouped_df[["name", "selector"]]

    def _log_filtered_domains(self) -> None:
        """Log summary of domains filtered for DCF 8.0 compatibility."""
        if self.all_invalid_domains:
            invalid_count = len(self.all_invalid_domains)
            logging.warning(f"Total DCF 8.0 incompatible SNI domains filtered: {invalid_count}")

            # Group by webgroup for detailed reporting
            by_webgroup = defaultdict(list)
            for item in self.all_invalid_domains:
                by_webgroup[item["webgroup"]].append(item["domain"])

            for webgroup, domains in by_webgroup.items():
                logging.warning(
                    f"Webgroup '{webgroup}' had {len(domains)} filtered domains: {domains}"
                )


class WebGroupManager:
    """High-level manager for WebGroup operations."""

    def __init__(self, unsupported_fqdn_tracker: Optional[UnsupportedFQDNTracker] = None, unsupported_cidr_tracker: Optional[UnsupportedCIDRTracker] = None, skip_incompatible_domain_filtering: bool = False) -> None:
        self.builder = WebGroupBuilder(unsupported_fqdn_tracker, unsupported_cidr_tracker, skip_incompatible_domain_filtering)
        self.unsupported_fqdn_tracker = self.builder.unsupported_fqdn_tracker
        self.unsupported_cidr_tracker = self.builder.unsupported_cidr_tracker

    def create_webgroups_from_fqdn_rules(self, fqdn_tag_rule_df: pd.DataFrame) -> pd.DataFrame:
        """
        Create WebGroups from FQDN tag rules for web traffic.

        Args:
            fqdn_tag_rule_df: DataFrame containing FQDN tag rules suitable for WebGroups

        Returns:
            DataFrame with WebGroup configurations
        """
        logging.info(f"Creating WebGroups from {len(fqdn_tag_rule_df)} FQDN tag rules")

        webgroups_df = self.builder.build_webgroup_dataframe(fqdn_tag_rule_df)

        logging.info(f"Created {len(webgroups_df)} WebGroups")
        return webgroups_df

    def validate_webgroup_constraints(self, webgroups_df: pd.DataFrame) -> pd.DataFrame:
        """
        Validate WebGroup configurations against DCF constraints.

        Args:
            webgroups_df: DataFrame with WebGroup configurations

        Returns:
            Validated DataFrame (may have some groups removed/modified)
        """
        max_name_length = DCF_CONSTRAINTS["max_web_group_name_length"]

        # Check for name length violations
        long_names = webgroups_df[webgroups_df["name"].str.len() > max_name_length]
        if len(long_names) > 0:
            logging.warning(
                f"Found {len(long_names)} WebGroups with names exceeding "
                f"{max_name_length} characters"
            )
            for _, row in long_names.iterrows():
                logging.warning(
                    f"WebGroup name too long: '{row['name'][:50]}...' (length: {len(row['name'])})"
                )

        # Keep only valid WebGroups
        valid_webgroups = webgroups_df[webgroups_df["name"].str.len() <= max_name_length]

        if len(valid_webgroups) < len(webgroups_df):
            removed_count = len(webgroups_df) - len(valid_webgroups)
            logging.warning(f"Removed {removed_count} WebGroups due to constraint violations")

        return valid_webgroups


# Legacy function wrappers for backward compatibility
def build_webgroup_df(fqdn_tag_rule_df: pd.DataFrame) -> pd.DataFrame:
    """
    Legacy wrapper for building WebGroups DataFrame.

    Args:
        fqdn_tag_rule_df: DataFrame with FQDN tag rules

    Returns:
        DataFrame with WebGroup configurations
    """
    manager = WebGroupManager()
    return manager.create_webgroups_from_fqdn_rules(fqdn_tag_rule_df)


def translate_fqdn_tag_to_sg_selector(fqdn_list: List[str]) -> Dict[str, Any]:
    """
    Legacy wrapper for FQDN to selector translation.

    Args:
        fqdn_list: List of FQDN strings

    Returns:
        WebGroup selector dictionary
    """
    builder = WebGroupBuilder()
    return builder._translate_fqdn_to_selector(fqdn_list)
