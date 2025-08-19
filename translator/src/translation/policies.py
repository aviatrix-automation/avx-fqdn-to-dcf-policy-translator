"""
Policy translation logic for the legacy-to-DCF policy translator.

This module handles the translation of legacy firewall policies to DCF format,
including L4 policies, internet policies, catch-all policies, and hostname policies.
"""

import logging
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from config import TranslationConfig
from config.defaults import POLICY_PRIORITIES
from data.processors import DataCleaner
from utils.data_processing import is_ipv4, translate_port_to_port_range, normalize_protocol


class PolicyBuilder:
    """Base class for building DCF policies from legacy configurations."""

    def __init__(self, internet_sg_id: str, anywhere_sg_id: str):
        self.internet_sg_id = internet_sg_id
        self.anywhere_sg_id = anywhere_sg_id

    def create_smartgroup_reference(self, sg_name: str) -> str:
        """Create Terraform reference for a SmartGroup."""
        return f"${{aviatrix_smart_group.{sg_name}.id}}"

    def _deduplicate_policy_names(self, policies_df: pd.DataFrame) -> pd.DataFrame:
        """Deduplicate policy names by adding numeric suffixes."""
        if len(policies_df) == 0:
            return policies_df

        name_counts: Dict[str, int] = {}
        new_names = []

        for name in policies_df["name"]:
            if name in name_counts:
                name_counts[name] += 1
                new_names.append(f"{name}_{name_counts[name]}")
            else:
                name_counts[name] = 0
                new_names.append(name)

        policies_df = policies_df.copy()
        policies_df["name"] = new_names
        return policies_df

    def _add_priorities(self, policies_df: pd.DataFrame, base_priority: int) -> pd.DataFrame:
        """Add priority values to policies."""
        policies_df = policies_df.reset_index(drop=True)
        policies_df.index = policies_df.index + base_priority
        policies_df["priority"] = policies_df.index
        return policies_df


class L4PolicyBuilder(PolicyBuilder):
    """Builds L4/stateful firewall DCF policies."""

    def __init__(self, internet_sg_id: str, anywhere_sg_id: str):
        super().__init__(internet_sg_id, anywhere_sg_id)
        self.cleaner = DataCleaner(TranslationConfig())

    def build_l4_policies(self, fw_policy_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build L4 DCF policies from legacy firewall policies.

        Args:
            fw_policy_df: DataFrame with legacy firewall policy data

        Returns:
            DataFrame with DCF L4 policies
        """
        if len(fw_policy_df) == 0:
            logging.info("No firewall policies to translate")
            return pd.DataFrame()

        logging.info(f"Building L4 DCF policies from {len(fw_policy_df)} legacy policies")

        # Consolidate policies to have multiple ports
        consolidated_df = (
            fw_policy_df.groupby(["src_ip", "dst_ip", "protocol", "action", "log_enabled"])["port"]
            .apply(list)
            .reset_index()
        )

        # Convert ports to port ranges
        consolidated_df["port_ranges"] = consolidated_df["port"].apply(translate_port_to_port_range)

        # Update source and destination to match SmartGroup naming
        for column in ["src_ip", "dst_ip"]:
            consolidated_df[column] = consolidated_df[column].apply(
                lambda x: "cidr_" + x if is_ipv4(x) else x
            )
            consolidated_df = self.cleaner.remove_invalid_name_chars(consolidated_df, column)

        # Create SmartGroup references
        consolidated_df["src_smart_groups"] = consolidated_df["src_ip"].apply(
            lambda x: [self.create_smartgroup_reference(x)]
        )
        consolidated_df["dst_smart_groups"] = consolidated_df["dst_ip"].apply(
            lambda x: [self.create_smartgroup_reference(x)]
        )

        # Convert actions and other fields to DCF format
        consolidated_df["action"] = consolidated_df["action"].apply(
            lambda x: "PERMIT" if x == "allow" else "DENY"
        )
        consolidated_df["logging"] = consolidated_df["log_enabled"].apply(
            lambda x: False if x == "FALSE" else True
        )
        # Use normalize_protocol function for proper protocol mapping
        consolidated_df["protocol"] = consolidated_df["protocol"].apply(normalize_protocol)

        # Generate policy names
        consolidated_df["name"] = consolidated_df.apply(
            lambda row: f"{row['src_ip']}_{row['dst_ip']}", axis=1
        )

        # Select final columns
        policy_df = consolidated_df[
            [
                "src_smart_groups",
                "dst_smart_groups",
                "action",
                "logging",
                "protocol",
                "name",
                "port_ranges",
            ]
        ]

        # Deduplicate policy names and add priorities
        policy_df = self._deduplicate_policy_names(policy_df)
        policy_df = self._add_priorities(policy_df, POLICY_PRIORITIES["l4_policies"])

        logging.info(f"Created {len(policy_df)} L4 DCF policies")
        return policy_df


class InternetPolicyBuilder(PolicyBuilder):
    """Builds internet egress policies for FQDN traffic."""

    def __init__(
        self,
        internet_sg_id: str,
        anywhere_sg_id: str,
        default_web_port_ranges: List[str],
        any_webgroup_id: str,
    ):
        super().__init__(internet_sg_id, anywhere_sg_id)
        self.default_web_port_ranges = default_web_port_ranges
        self.any_webgroup_id = any_webgroup_id
        self.cleaner = DataCleaner(TranslationConfig())

    def build_internet_policies(
        self, gateways_df: pd.DataFrame, fqdn_df: pd.DataFrame, webgroups_df: pd.DataFrame,
        hostname_smartgroups_df: pd.DataFrame = None, hostname_rules_df: pd.DataFrame = None
    ) -> pd.DataFrame:
        """
        Build internet egress policies for FQDN traffic (both webgroup and hostname-based).
        
        DEPRECATED: Use build_webgroup_policies() and build_hostname_policies() separately
        for proper priority ordering.

        Args:
            gateways_df: DataFrame with gateway details
            fqdn_df: DataFrame with FQDN tag configurations
            webgroups_df: DataFrame with WebGroup configurations
            hostname_smartgroups_df: DataFrame with hostname SmartGroup configurations
            hostname_rules_df: DataFrame with hostname rules

        Returns:
            DataFrame with internet egress policies
        """
        logging.warning("build_internet_policies is deprecated. Use build_webgroup_policies() and build_hostname_policies() separately.")
        
        # For backward compatibility, build both and combine
        hostname_policies = self.build_hostname_policies(gateways_df, fqdn_df, hostname_smartgroups_df, hostname_rules_df)
        webgroup_policies = self.build_webgroup_policies(gateways_df, fqdn_df, webgroups_df)
        
        policy_dataframes = []
        if len(hostname_policies) > 0:
            policy_dataframes.append(hostname_policies)
        if len(webgroup_policies) > 0:
            policy_dataframes.append(webgroup_policies)
            
        if not policy_dataframes:
            return pd.DataFrame()
            
        return pd.concat(policy_dataframes, ignore_index=True)

    def build_hostname_policies(
        self, gateways_df: pd.DataFrame, fqdn_df: pd.DataFrame, 
        hostname_smartgroups_df: pd.DataFrame = None, hostname_rules_df: pd.DataFrame = None
    ) -> pd.DataFrame:
        """
        Build hostname-based policies for FQDN traffic.

        Args:
            gateways_df: DataFrame with gateway details
            fqdn_df: DataFrame with FQDN tag configurations
            hostname_smartgroups_df: DataFrame with hostname SmartGroup configurations
            hostname_rules_df: DataFrame with hostname rules

        Returns:
            DataFrame with hostname policies
        """
        logging.info("Building hostname policies")

        # Get egress VPCs (non-HAGW with NAT enabled)
        egress_vpcs = self._get_egress_vpcs(gateways_df)
        if len(egress_vpcs) == 0:
            logging.info("No egress VPCs found")
            return pd.DataFrame()

        # Process FQDN tags and clean disabled tags
        egress_vpcs = self._process_fqdn_tags(egress_vpcs, fqdn_df)

        # Build hostname policies
        hostname_policy_dataframes = []

        # Hostname policies (both VPC-level and source IP-specific)
        if hostname_smartgroups_df is not None and hostname_rules_df is not None:
            # VPC-level hostname policies (exclude source IP tags)
            vpc_hostname_policies = self._build_vpc_hostname_policies(
                gateways_df, fqdn_df, hostname_smartgroups_df, hostname_rules_df
            )
            if len(vpc_hostname_policies) > 0:
                hostname_policy_dataframes.append(vpc_hostname_policies)

            # Source IP hostname policies (source IP tags only)
            source_ip_hostname_policies = self._build_source_ip_hostname_policies(
                fqdn_df, hostname_smartgroups_df, hostname_rules_df
            )
            if len(source_ip_hostname_policies) > 0:
                hostname_policy_dataframes.append(source_ip_hostname_policies)

        # Merge hostname policies
        if not hostname_policy_dataframes:
            logging.info("No hostname policies created")
            return pd.DataFrame()

        hostname_policies = pd.concat(hostname_policy_dataframes, ignore_index=True)

        # Remove duplicates based on policy configuration fields
        # Handle list columns by converting them to strings for comparison
        dedup_columns = ['src_smart_groups', 'dst_smart_groups', 'action', 'protocol', 'port_ranges', 'web_groups']
        initial_count = len(hostname_policies)
        
        # Create a temporary DataFrame with string representations of list columns for deduplication
        temp_df = hostname_policies.copy()
        for col in dedup_columns:
            if col in temp_df.columns:
                # Convert lists to sorted tuples (then to strings) for consistent comparison
                temp_df[col] = temp_df[col].apply(
                    lambda x: str(tuple(sorted(x))) if isinstance(x, list) else str(x)
                )
        
        # Find duplicates using the string representations
        duplicate_mask = temp_df.duplicated(subset=dedup_columns, keep='first')
        hostname_policies = hostname_policies[~duplicate_mask].reset_index(drop=True)
        final_count = len(hostname_policies)
        
        if initial_count > final_count:
            logging.info(f"Removed {initial_count - final_count} duplicate hostname policies")
        
        hostname_policies = self._deduplicate_policy_names(hostname_policies)
        
        # Add priorities - hostname policies start at 500
        hostname_policies = hostname_policies.reset_index(drop=True)
        hostname_policies.index = hostname_policies.index + POLICY_PRIORITIES["hostname_policies"]
        hostname_policies["priority"] = hostname_policies.index

        logging.info(f"Created {len(hostname_policies)} hostname policies")
        return hostname_policies

    def build_webgroup_policies(
        self, gateways_df: pd.DataFrame, fqdn_df: pd.DataFrame, webgroups_df: pd.DataFrame
    ) -> pd.DataFrame:
        """
        Build webgroup-based policies for FQDN traffic.

        Args:
            gateways_df: DataFrame with gateway details
            fqdn_df: DataFrame with FQDN tag configurations
            webgroups_df: DataFrame with WebGroup configurations

        Returns:
            DataFrame with webgroup policies
        """
        logging.info("Building webgroup policies")

        # Get egress VPCs (non-HAGW with NAT enabled)
        egress_vpcs = self._get_egress_vpcs(gateways_df)
        if len(egress_vpcs) == 0:
            logging.info("No egress VPCs found")
            return pd.DataFrame()

        # Process FQDN tags and clean disabled tags
        egress_vpcs = self._process_fqdn_tags(egress_vpcs, fqdn_df)

        # Build webgroup policies
        webgroup_policy_dataframes = []

        # 1. FQDN tag-specific policies (webgroup-based)
        fqdn_policies = self._build_fqdn_tag_policies(egress_vpcs, fqdn_df, webgroups_df)
        if len(fqdn_policies) > 0:
            webgroup_policy_dataframes.append(fqdn_policies)

        # 2. Source IP list FQDN policies (for FQDN tags with source_ip_list SmartGroups)
        source_ip_policies = self._build_source_ip_fqdn_policies(fqdn_df, webgroups_df)
        if len(source_ip_policies) > 0:
            webgroup_policy_dataframes.append(source_ip_policies)

        # 3. Default policies for FQDN tags
        default_policies = self._build_fqdn_default_policies(egress_vpcs, fqdn_df)
        if len(default_policies) > 0:
            webgroup_policy_dataframes.append(default_policies)

        # 4. Discovery mode policies
        discovery_policies = self._build_discovery_policies(egress_vpcs)
        if len(discovery_policies) > 0:
            webgroup_policy_dataframes.extend(discovery_policies)

        # 5. NAT-only policies
        nat_only_policies = self._build_nat_only_policies(egress_vpcs)
        if len(nat_only_policies) > 0:
            webgroup_policy_dataframes.append(nat_only_policies)

        # Merge webgroup policies
        if not webgroup_policy_dataframes:
            logging.info("No webgroup policies created")
            return pd.DataFrame()

        webgroup_policies = pd.concat(webgroup_policy_dataframes, ignore_index=True)

        # Sort and prioritize policies
        def get_policy_priority(row: pd.Series) -> int:
            web_groups = row["web_groups"]
            # Check if web_groups is None, NaN, empty list, or contains None values
            if web_groups is None:
                is_default_policy = True
            elif isinstance(web_groups, list):
                is_default_policy = len(web_groups) == 0 or all(x is None for x in web_groups)
            else:
                try:
                    is_default_policy = pd.isna(web_groups)
                except (ValueError, TypeError):
                    is_default_policy = False

            return 2 if is_default_policy else 1  # Default policies come after specific policies

        webgroup_policies["sort_priority"] = webgroup_policies.apply(get_policy_priority, axis=1)
        webgroup_policies = webgroup_policies.sort_values(["sort_priority"]).drop(
            columns=["sort_priority"]
        )
        webgroup_policies = webgroup_policies.reset_index(drop=True)

        # Deduplicate policy names
        webgroup_policies = self._deduplicate_policy_names(webgroup_policies)

        # Add priorities - webgroup policies start at 1000
        webgroup_policies.index = webgroup_policies.index + POLICY_PRIORITIES["webgroup_policies"]
        webgroup_policies["priority"] = webgroup_policies.index

        logging.info(f"Created {len(webgroup_policies)} webgroup policies")
        return webgroup_policies

    def _get_egress_vpcs(self, gateways_df: pd.DataFrame) -> pd.DataFrame:
        """Get egress VPCs (non-HAGW with egress control enabled)."""
        if len(gateways_df) == 0:
            return pd.DataFrame()

        egress_vpcs = gateways_df[
            (gateways_df["is_hagw"] == "no") & (gateways_df["egress_control"] == "Enabled")
        ].drop_duplicates(subset=["vpc_id", "vpc_region", "account_name"])

        return egress_vpcs[["fqdn_tags", "stateful_fw", "egress_control", "vpc_name", "vpc_id"]]

    def _process_fqdn_tags(self, egress_vpcs: pd.DataFrame, fqdn_df: pd.DataFrame) -> pd.DataFrame:
        """Process and clean FQDN tags for egress VPCs."""

        egress_vpcs["src_smart_groups"] = egress_vpcs["vpc_id"]
        egress_vpcs["src_smart_groups"] = self.cleaner.pretty_parse_vpc_name(egress_vpcs, "src_smart_groups")
        egress_vpcs["src_smart_groups"] = egress_vpcs["src_smart_groups"].apply(
            lambda x: self.create_smartgroup_reference(x)
        )

        # Clean up disabled tag references
        disabled_tag_names = list(fqdn_df[~fqdn_df["fqdn_enabled"]]["fqdn_tag"])
        if disabled_tag_names:
            egress_vpcs_with_disabled = egress_vpcs[
                egress_vpcs["fqdn_tags"].apply(
                    lambda x: any(item in disabled_tag_names for item in x)
                )
            ]
            if len(egress_vpcs_with_disabled) > 0:
                logging.warning(
                    f"{len(egress_vpcs_with_disabled)} VPCs have disabled FQDN tags. "
                    f"Policies for these tags will be ignored."
                )

            egress_vpcs["fqdn_tags"] = egress_vpcs["fqdn_tags"].apply(
                lambda x: [item for item in x if item not in disabled_tag_names]
            )

        return egress_vpcs

    def _build_fqdn_tag_policies(
        self, egress_vpcs: pd.DataFrame, fqdn_df: pd.DataFrame, webgroups_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Build FQDN tag-specific policies using WebGroups."""
        
        # Ensure fqdn_df has the has_source_ip_filter column
        if "has_source_ip_filter" not in fqdn_df.columns:
            fqdn_df = fqdn_df.copy()
            fqdn_df["has_source_ip_filter"] = False
        
        egress_vpcs_with_enabled_tags = (
            egress_vpcs.explode("fqdn_tags")
            .rename(columns={"fqdn_tags": "fqdn_tag"})
            .merge(fqdn_df, on="fqdn_tag", how="left")
        )

        egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags[
            egress_vpcs_with_enabled_tags["fqdn_enabled"].fillna(False)
        ]

        # EXCLUDE FQDN tags that have source IP filters - they should only be handled by _build_source_ip_fqdn_policies
        # Ensure the has_source_ip_filter column exists before filtering
        if "has_source_ip_filter" not in egress_vpcs_with_enabled_tags.columns:
            logging.warning(f"Adding missing has_source_ip_filter column to merged DataFrame. Current columns: {list(egress_vpcs_with_enabled_tags.columns)}")
            egress_vpcs_with_enabled_tags["has_source_ip_filter"] = False
        
        # Debug log the columns and shape
        logging.debug(f"egress_vpcs_with_enabled_tags shape: {egress_vpcs_with_enabled_tags.shape}, columns: {list(egress_vpcs_with_enabled_tags.columns)}")
        
        # Use a different approach to filtering to avoid the pandas KeyError
        try:
            # First ensure the column exists and has valid values
            if "has_source_ip_filter" not in egress_vpcs_with_enabled_tags.columns:
                egress_vpcs_with_enabled_tags["has_source_ip_filter"] = False
            
            # Replace any NaN values with False
            egress_vpcs_with_enabled_tags["has_source_ip_filter"] = egress_vpcs_with_enabled_tags["has_source_ip_filter"].fillna(False)
            
            # Apply the filter using .loc to avoid indexing issues
            mask = ~egress_vpcs_with_enabled_tags["has_source_ip_filter"]
            egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags.loc[mask].copy()
            
        except Exception as e:
            logging.error(f"Error filtering has_source_ip_filter: {e}. Proceeding without filtering.")
            # If there's still an issue, just continue without the filter
            pass

        # If no FQDN tags remain after filtering out source IP filtered ones, return empty
        if egress_vpcs_with_enabled_tags.empty:
            logging.info("No FQDN tags without source IP filters found for VPC-level policies")
            return pd.DataFrame()

        egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags.rename(
            columns={"fqdn_tag": "fqdn_tag_name"}
        )

        fqdn_tag_policies = egress_vpcs_with_enabled_tags.merge(
            webgroups_df, on=["fqdn_tag_name", "fqdn_mode"], how="left"
        )

        # Create WebGroup references
        fqdn_tag_policies["web_groups"] = fqdn_tag_policies["name"].apply(
            lambda x: f"${{aviatrix_web_group.{x}.id}}" if pd.notna(x) else None
        )

        # Group by VPC and FQDN configuration
        fqdn_tag_policies = (
            fqdn_tag_policies.groupby(
                ["src_smart_groups", "vpc_name", "protocol", "port", "fqdn_mode"]
            )["web_groups"]
            .apply(list)
            .reset_index()
        )

        fqdn_tag_policies["src_smart_groups"] = fqdn_tag_policies["src_smart_groups"].apply(
            lambda x: [x]
        )
        fqdn_tag_policies["dst_smart_groups"] = fqdn_tag_policies.apply(
            lambda x: [self.internet_sg_id], axis=1
        )
        fqdn_tag_policies["action"] = fqdn_tag_policies["fqdn_mode"].apply(
            lambda x: "PERMIT" if x == "white" else "DENY"
        )
        fqdn_tag_policies["port_ranges"] = fqdn_tag_policies["port"].apply(
            lambda x: translate_port_to_port_range([x])
        )
        fqdn_tag_policies["logging"] = True
        fqdn_tag_policies["protocol"] = fqdn_tag_policies["protocol"].apply(normalize_protocol)
        fqdn_tag_policies["name"] = fqdn_tag_policies.apply(
            lambda row: f"Egress_{row['vpc_name']}_"
            f"{'permit' if row['fqdn_mode'] == 'white' else 'deny'}",
            axis=1,
        )

        return fqdn_tag_policies[
            [
                "src_smart_groups",
                "dst_smart_groups",
                "action",
                "port_ranges",
                "logging",
                "protocol",
                "name",
                "web_groups",
            ]
        ]

    def _build_fqdn_default_policies(
        self, egress_vpcs: pd.DataFrame, fqdn_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Build default policies for FQDN tags based on default action."""
        
        # Ensure fqdn_df has the has_source_ip_filter column
        if "has_source_ip_filter" not in fqdn_df.columns:
            fqdn_df = fqdn_df.copy()
            fqdn_df["has_source_ip_filter"] = False
        
        egress_vpcs_with_enabled_tags = (
            egress_vpcs.explode("fqdn_tags")
            .rename(columns={"fqdn_tags": "fqdn_tag"})
            .merge(fqdn_df, on="fqdn_tag", how="left")
        )

        egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags[
            egress_vpcs_with_enabled_tags["fqdn_enabled"].fillna(False)
        ]

        # EXCLUDE FQDN tags that have source IP filters - they should only be handled by _build_source_ip_fqdn_policies
        # Use a different approach to filtering to avoid the pandas KeyError
        try:
            # First ensure the column exists and has valid values
            if "has_source_ip_filter" not in egress_vpcs_with_enabled_tags.columns:
                egress_vpcs_with_enabled_tags["has_source_ip_filter"] = False
            
            # Replace any NaN values with False
            egress_vpcs_with_enabled_tags["has_source_ip_filter"] = egress_vpcs_with_enabled_tags["has_source_ip_filter"].fillna(False)
            
            # Apply the filter using .loc to avoid indexing issues
            mask = ~egress_vpcs_with_enabled_tags["has_source_ip_filter"]
            egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags.loc[mask].copy()
            
        except Exception as e:
            logging.error(f"Error filtering has_source_ip_filter in _build_fqdn_default_policies: {e}. Proceeding without filtering.")
            # If there's still an issue, just continue without the filter
            pass

        # If no FQDN tags remain after filtering, return empty
        if egress_vpcs_with_enabled_tags.empty:
            logging.info("No FQDN tags without source IP filters found for default policies")
            return pd.DataFrame()

        fqdn_tag_default_policies = (
            egress_vpcs_with_enabled_tags.groupby(["fqdn_mode"])["src_smart_groups"]
            .apply(list)
            .reset_index()
        )

        fqdn_tag_default_policies["dst_smart_groups"] = fqdn_tag_default_policies.apply(
            lambda x: [self.internet_sg_id], axis=1
        )
        fqdn_tag_default_policies["logging"] = True
        fqdn_tag_default_policies["protocol"] = "ANY"
        fqdn_tag_default_policies["port_ranges"] = None
        fqdn_tag_default_policies["web_groups"] = None
        fqdn_tag_default_policies["action"] = fqdn_tag_default_policies["fqdn_mode"].apply(
            lambda x: "DENY" if x == "white" else "PERMIT"
        )
        fqdn_tag_default_policies["name"] = fqdn_tag_default_policies["fqdn_mode"].apply(
            lambda x: "Egress-Permit-Default" if x == "white" else "Egress-Deny-Default"
        )

        return fqdn_tag_default_policies.drop(columns="fqdn_mode")

    def _build_source_ip_fqdn_policies(
        self, fqdn_df: pd.DataFrame, webgroups_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Build internet policies for FQDN tags that have source_ip_list SmartGroups."""
        logging.info(f"_build_source_ip_fqdn_policies called with fqdn_df: {len(fqdn_df)} rows, webgroups_df: {len(webgroups_df)} rows")

        # Add has_source_ip_filter column if it doesn't exist
        if "has_source_ip_filter" not in fqdn_df.columns:
            fqdn_df = fqdn_df.copy()
            fqdn_df["has_source_ip_filter"] = False

        # Filter FQDN tags that have source IP filters and are enabled
        source_ip_fqdns = fqdn_df[
            fqdn_df["has_source_ip_filter"] & fqdn_df["fqdn_enabled"]
        ].copy()

        logging.info(f"Filtered to {len(source_ip_fqdns)} FQDN tags with source IP filters and enabled")

        if source_ip_fqdns.empty:
            logging.info("No enabled FQDN tags with source IP filters found")
            return pd.DataFrame()

        logging.info(f"Building policies for {len(source_ip_fqdns)} FQDN tags with source IP filters")

        # Create policies for each FQDN tag with webgroups
        source_ip_policies = source_ip_fqdns.merge(
            webgroups_df, left_on=["fqdn_tag", "fqdn_mode"], right_on=["fqdn_tag_name", "fqdn_mode"], how="left"
        )

        # Create WebGroup references
        source_ip_policies["web_groups"] = source_ip_policies["name"].apply(
            lambda x: f"${{aviatrix_web_group.{x}.id}}" if pd.notna(x) else None
        )

        # Group by FQDN tag and configuration
        source_ip_policies = (
            source_ip_policies.groupby(
                ["fqdn_tag", "protocol", "port", "fqdn_mode"]
            )["web_groups"]
            .apply(list)
            .reset_index()
        )

        # Build policy structure
        source_ip_policies["src_smart_groups"] = source_ip_policies["fqdn_tag"].apply(
            lambda x: [self.create_smartgroup_reference(self._clean_fqdn_tag_name(x))]
        )
        source_ip_policies["dst_smart_groups"] = source_ip_policies.apply(
            lambda x: [self.internet_sg_id], axis=1
        )
        source_ip_policies["action"] = source_ip_policies["fqdn_mode"].apply(
            lambda x: "PERMIT" if x == "white" else "DENY"
        )
        source_ip_policies["port_ranges"] = source_ip_policies["port"].apply(
            lambda x: translate_port_to_port_range([x])
        )
        source_ip_policies["logging"] = True
        source_ip_policies["protocol"] = source_ip_policies["protocol"].apply(normalize_protocol)
        source_ip_policies["name"] = source_ip_policies.apply(
            lambda row: f"Egress_{self._clean_fqdn_tag_name(row['fqdn_tag'])}_"
            f"{'permit' if row['fqdn_mode'] == 'white' else 'deny'}",
            axis=1,
        )

        return source_ip_policies[
            [
                "src_smart_groups",
                "dst_smart_groups",
                "action",
                "port_ranges",
                "logging",
                "protocol",
                "name",
                "web_groups",
            ]
        ]

    def _clean_fqdn_tag_name(self, fqdn_tag: str) -> str:
        """Clean FQDN tag name for SmartGroup reference."""
        # Use the same cleaning logic as the source IP SmartGroup manager
        temp_df = pd.DataFrame({"name": [fqdn_tag]})
        cleaned_df = self.cleaner.remove_invalid_name_chars(temp_df, "name")
        return str(cleaned_df["name"].iloc[0])

    def _build_discovery_policies(self, egress_vpcs: pd.DataFrame) -> List[pd.DataFrame]:
        """Build discovery mode policies for L7 and L4 traffic."""
        egress_vpcs_with_discovery = egress_vpcs[
            egress_vpcs["fqdn_tags"].astype(str).str.contains("-discovery")
        ]

        if egress_vpcs_with_discovery.empty:
            return []

        discovery_policies = []

        # L7 Discovery policy (web traffic with any webgroup)
        discovery_l7 = pd.DataFrame(
            [
                {
                    "src_smart_groups": list(egress_vpcs_with_discovery["src_smart_groups"]),
                    "dst_smart_groups": [self.internet_sg_id],
                    "action": "PERMIT",
                    "logging": True,
                    "protocol": "TCP",
                    "name": "Egress-Discovery-L7",
                    "port_ranges": translate_port_to_port_range(self.default_web_port_ranges),
                    "web_groups": [self.any_webgroup_id],
                }
            ]
        )
        discovery_policies.append(discovery_l7)

        # L4 Discovery policy (all other traffic)
        discovery_l4 = pd.DataFrame(
            [
                {
                    "src_smart_groups": list(egress_vpcs_with_discovery["src_smart_groups"]),
                    "dst_smart_groups": [self.internet_sg_id],
                    "action": "PERMIT",
                    "logging": True,
                    "protocol": "ANY",
                    "name": "Egress-Discovery-L4",
                    "port_ranges": None,
                    "web_groups": None,
                }
            ]
        )
        discovery_policies.append(discovery_l4)

        return discovery_policies

    def _build_nat_only_policies(self, egress_vpcs: pd.DataFrame) -> pd.DataFrame:
        """Build policies for egress VPCs that only have NAT and no FQDN tags."""
        egress_vpcs_with_nat_only = egress_vpcs[egress_vpcs["fqdn_tags"].astype(str) == "[]"]

        if egress_vpcs_with_nat_only.empty:
            return pd.DataFrame()

        nat_only_policies = pd.DataFrame(
            [
                {
                    "src_smart_groups": list(egress_vpcs_with_nat_only["src_smart_groups"]),
                    "dst_smart_groups": [self.internet_sg_id],
                    "action": "PERMIT",
                    "logging": True,
                    "protocol": "ANY",
                    "name": "Egress-Allow-All",
                    "port_ranges": None,
                    "web_groups": None,
                }
            ]
        )

        return nat_only_policies

    def _sort_and_prioritize_policies(self, internet_policies: pd.DataFrame) -> pd.DataFrame:
        """Sort policies and assign priorities."""

        def get_policy_priority(row: pd.Series) -> int:
            web_groups = row["web_groups"]
            # Check if web_groups is None, NaN, empty list, or contains None values
            if web_groups is None:
                is_default_policy = True
            elif isinstance(web_groups, list):
                is_default_policy = len(web_groups) == 0 or all(x is None for x in web_groups)
            else:
                try:
                    is_default_policy = pd.isna(web_groups)
                except (ValueError, TypeError):
                    is_default_policy = False

            return 2 if is_default_policy else 1  # Default policies come after specific policies

        internet_policies["sort_priority"] = internet_policies.apply(get_policy_priority, axis=1)
        internet_policies = internet_policies.sort_values(["sort_priority"]).drop(
            columns=["sort_priority"]
        )
        internet_policies = internet_policies.reset_index(drop=True)

        # Deduplicate policy names
        internet_policies = self._deduplicate_policy_names(internet_policies)

        # Add priorities (internet policies start at 2000)
        internet_policies.index = internet_policies.index + POLICY_PRIORITIES["internet_policies"]
        internet_policies["priority"] = internet_policies.index

        return internet_policies

    def _build_source_ip_hostname_policies(
        self, fqdn_df: pd.DataFrame, hostname_smartgroups_df: pd.DataFrame, hostname_rules_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Build hostname policies for FQDN tags that have source_ip_list SmartGroups."""
        logging.info(f"_build_source_ip_hostname_policies called with fqdn_df: {len(fqdn_df)} rows, hostname_smartgroups_df: {len(hostname_smartgroups_df)} rows")

        # Add has_source_ip_filter column if it doesn't exist
        if "has_source_ip_filter" not in fqdn_df.columns:
            fqdn_df = fqdn_df.copy()
            fqdn_df["has_source_ip_filter"] = False

        # Filter FQDN tags that have source IP filters and are enabled
        source_ip_fqdns = fqdn_df[
            fqdn_df["has_source_ip_filter"] & fqdn_df["fqdn_enabled"]
        ].copy()

        logging.info(f"Filtered to {len(source_ip_fqdns)} FQDN tags with source IP filters and enabled")

        if source_ip_fqdns.empty or hostname_smartgroups_df.empty:
            logging.info("No enabled FQDN tags with source IP filters or no hostname SmartGroups found")
            return pd.DataFrame()

        logging.info(f"Building hostname policies for {len(source_ip_fqdns)} FQDN tags with source IP filters")

        # Create hostname SmartGroup mapping for efficient lookup
        # We need to match source IP FQDN tags to hostname SmartGroups by fqdn_tag_name, protocol, port, and mode
        hostname_sg_map = {}
        for _, sg_row in hostname_smartgroups_df.iterrows():
            # Extract fqdn_tag_name from the SmartGroup name (format: fqdn_{fqdn_tag_name}_{hash})
            sg_name = sg_row["name"]
            if sg_name.startswith("fqdn_"):
                # Extract the fqdn_tag_name by removing the prefix and hash suffix
                name_parts = sg_name[5:]  # Remove "fqdn_" prefix
                # Find the last underscore to separate tag name from hash
                last_underscore = name_parts.rfind("_")
                if last_underscore > 0:
                    extracted_fqdn_tag_name = name_parts[:last_underscore]
                    # Convert underscores back to spaces to match original FQDN tag names
                    original_fqdn_tag_name = extracted_fqdn_tag_name.replace("_", " ")
                    protocol = sg_row["protocol"]
                    port = sg_row["port"]
                    fqdn_mode = sg_row["fqdn_mode"]

                    # Create unique key for this SmartGroup
                    key = (original_fqdn_tag_name, protocol, port, fqdn_mode)
                    hostname_sg_map[key] = sg_row

        logging.info(f"Created hostname SmartGroup map with {len(hostname_sg_map)} entries")

        # Now create policies by matching source IP FQDN tags to their corresponding hostname SmartGroups
        hostname_policies = []
        for _, fqdn_row in source_ip_fqdns.iterrows():
            fqdn_tag = fqdn_row["fqdn_tag"]
            fqdn_mode = fqdn_row["fqdn_mode"]
            cleaned_fqdn_tag = self._clean_fqdn_tag_name(fqdn_tag)

            # Find hostname rules that match this FQDN tag
            matching_rules = hostname_rules_df[
                hostname_rules_df["fqdn_tag_name"] == fqdn_tag
            ]

            # For each matching rule, find the corresponding hostname SmartGroup
            for _, rule_row in matching_rules.iterrows():
                protocol = rule_row["protocol"]
                port = rule_row["port"]
                rule_fqdn_mode = rule_row["fqdn_mode"]

                # Look up the hostname SmartGroup for this specific combination
                key = (fqdn_tag, protocol, port, rule_fqdn_mode)

                if key in hostname_sg_map:
                    sg_row = hostname_sg_map[key]
                    sg_name = sg_row["name"]

                    src_sg_ref = f"${{aviatrix_smart_group.{cleaned_fqdn_tag}.id}}"
                    dst_sg_ref = f"${{aviatrix_smart_group.{sg_name}.id}}"

                    action = "PERMIT" if rule_fqdn_mode == "white" else "DENY"
                    policy_name = (
                        f"Hostname_{cleaned_fqdn_tag}_"
                        f"{'permit' if rule_fqdn_mode == 'white' else 'deny'}"
                    )

                    # Convert port to port_ranges format, handling special cases
                    if port == "ALL":
                        port_ranges = None  # No port restrictions for ALL
                    else:
                        port_ranges = translate_port_to_port_range([port]) if port else None

                    # Ensure protocol is properly formatted for DCF
                    dcf_protocol = normalize_protocol(protocol)

                    hostname_policies.append(
                        {
                            "src_smart_groups": [src_sg_ref],
                            "dst_smart_groups": [dst_sg_ref],
                            "action": action,
                            "logging": True,
                            "protocol": dcf_protocol,
                            "name": policy_name,
                            "port_ranges": port_ranges,
                            "web_groups": None,
                        }
                    )

        hostname_policies_df = pd.DataFrame(hostname_policies)
        logging.info(f"Created {len(hostname_policies_df)} source IP hostname-based policies")
        return hostname_policies_df

    def _build_vpc_hostname_policies(
        self, gateways_df: pd.DataFrame, fqdn_df: pd.DataFrame, hostname_smartgroups_df: pd.DataFrame, hostname_rules_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Build VPC-level hostname policies for FQDN tags WITHOUT source_ip_list."""
        logging.info(f"_build_vpc_hostname_policies called with gateways_df: {len(gateways_df)} rows")

        if hostname_smartgroups_df.empty or hostname_rules_df.empty:
            logging.info("No hostname SmartGroups or hostname rules found")
            return pd.DataFrame()

        # Get egress VPCs (same logic as in other policy builders)
        egress_vpcs = self._get_egress_vpcs(gateways_df)
        if egress_vpcs.empty:
            logging.info("No egress VPCs found")
            return pd.DataFrame()

        # Process FQDN tags for egress VPCs
        egress_vpcs = self._process_fqdn_tags(egress_vpcs, fqdn_df)

        # EXCLUDE FQDN tags that have source IP filters - they should only be handled by _build_source_ip_hostname_policies
        
        # Ensure fqdn_df has the has_source_ip_filter column before merging
        if "has_source_ip_filter" not in fqdn_df.columns:
            fqdn_df = fqdn_df.copy()
            fqdn_df["has_source_ip_filter"] = False
        
        egress_vpcs_with_enabled_tags = egress_vpcs.explode("fqdn_tags").rename(
            columns={"fqdn_tags": "fqdn_tag"}
        )
        egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags.merge(
            fqdn_df, on="fqdn_tag", how="left"
        )
        
        # Ensure the has_source_ip_filter column exists before filtering
        if "has_source_ip_filter" not in egress_vpcs_with_enabled_tags.columns:
            egress_vpcs_with_enabled_tags["has_source_ip_filter"] = False
            
        egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags[
            egress_vpcs_with_enabled_tags["fqdn_enabled"].fillna(False) &
            ~egress_vpcs_with_enabled_tags["has_source_ip_filter"].fillna(False)
        ]

        if egress_vpcs_with_enabled_tags.empty:
            logging.info("No enabled FQDN tags without source IP filters found")
            return pd.DataFrame()

        egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags.rename(
            columns={"fqdn_tag": "fqdn_tag_name"}
        )

        # Match VPCs to hostname rules to determine which hostname smartgroups they should use
        vpc_hostname_matches = egress_vpcs_with_enabled_tags.merge(
            hostname_rules_df[["fqdn_tag_name", "protocol", "port", "fqdn_mode", "fqdn"]],
            on=["fqdn_tag_name", "fqdn_mode"],
            how="inner",
        )

        if vpc_hostname_matches.empty:
            logging.info("No VPC-hostname rule matches found")
            return pd.DataFrame()

        # Create hostname SmartGroup mapping for efficient lookup
        # We need to match VPC FQDN tags to hostname SmartGroups by fqdn_tag_name, protocol, port, and mode
        hostname_sg_map = {}
        for _, sg_row in hostname_smartgroups_df.iterrows():
            # Extract fqdn_tag_name from the SmartGroup name (format: fqdn_{fqdn_tag_name}_{hash})
            sg_name = sg_row["name"]
            if sg_name.startswith("fqdn_"):
                # Extract the fqdn_tag_name by removing the prefix and hash suffix
                name_parts = sg_name[5:]  # Remove "fqdn_" prefix
                # Find the last underscore to separate tag name from hash
                last_underscore = name_parts.rfind("_")
                if last_underscore > 0:
                    fqdn_tag_name = name_parts[:last_underscore]
                    protocol = sg_row["protocol"]
                    port = sg_row["port"]
                    fqdn_mode = sg_row["fqdn_mode"]

                    # Create unique key for this SmartGroup
                    key = (fqdn_tag_name, protocol, port, fqdn_mode)
                    hostname_sg_map[key] = sg_row

        # Now create policies by matching VPC FQDN tags to their corresponding hostname SmartGroups
        hostname_policies = []
        for _, vpc_row in vpc_hostname_matches.iterrows():
            fqdn_tag_name = vpc_row["fqdn_tag_name"]
            protocol = vpc_row["protocol"]
            port = vpc_row["port"]
            fqdn_mode = vpc_row["fqdn_mode"]
            src_sg_ref = vpc_row["src_smart_groups"]  # This is already a full reference
            vpc_display_name = vpc_row["vpc_name"]

            # Look up the hostname SmartGroup for this specific VPC's FQDN tag combination
            key = (fqdn_tag_name, protocol, port, fqdn_mode)
            if key in hostname_sg_map:
                sg_row = hostname_sg_map[key]
                sg_name = sg_row["name"]

                dst_sg_ref = f"${{aviatrix_smart_group.{sg_name}.id}}"

                action = "PERMIT" if fqdn_mode == "white" else "DENY"
                policy_name = (
                    f"VPC_Hostname_{vpc_display_name}_"
                    f"{'permit' if fqdn_mode == 'white' else 'deny'}"
                )

                # Convert port to port_ranges format, handling special cases
                if port == "ALL":
                    port_ranges = None  # No port restrictions for ALL
                else:
                    port_ranges = translate_port_to_port_range([port]) if port else None

                # Ensure protocol is properly formatted for DCF
                dcf_protocol = normalize_protocol(protocol)

                hostname_policies.append(
                    {
                        "src_smart_groups": [src_sg_ref],
                        "dst_smart_groups": [dst_sg_ref],
                        "action": action,
                        "logging": True,
                        "protocol": dcf_protocol,
                        "name": policy_name,
                        "port_ranges": port_ranges,
                        "web_groups": None,
                    }
                )

        hostname_policies_df = pd.DataFrame(hostname_policies)
        logging.info(f"Created {len(hostname_policies_df)} VPC-level hostname policies")
        return hostname_policies_df


class CatchAllPolicyBuilder(PolicyBuilder):
    """Builds catch-all policies based on VPC default policies."""

    def __init__(self, internet_sg_id: str, anywhere_sg_id: str, global_catch_all_action: str):
        super().__init__(internet_sg_id, anywhere_sg_id)
        self.global_catch_all_action = global_catch_all_action
        self.cleaner = DataCleaner(TranslationConfig())

    def build_catch_all_policies(
        self, gateways_df: pd.DataFrame, firewall_df: pd.DataFrame
    ) -> pd.DataFrame:
        """
        Build catch-all policies based on VPC default firewall policies.

        Args:
            gateways_df: DataFrame with gateway details
            firewall_df: DataFrame with firewall default policies

        Returns:
            DataFrame with catch-all policies
        """
        logging.info("Building catch-all policies")

        # Handle empty input - still create global catch-all policy
        if len(gateways_df) == 0:
            global_catch_all = self._build_global_catch_all()
            global_catch_all["web_groups"] = None
            global_catch_all["port_ranges"] = None
            global_catch_all["protocol"] = "ANY"
            global_catch_all["logging"] = True
            global_catch_all = global_catch_all.reset_index(drop=True)
            global_catch_all.index = global_catch_all.index + 3000
            global_catch_all["priority"] = global_catch_all.index
            logging.info(f"Created {len(global_catch_all)} catch-all policies (global only)")
            return global_catch_all

        # Remove HAGWs
        gateways_df = gateways_df[gateways_df["is_hagw"] == "no"]

        # Enrich gateway details with FW default policy
        if len(firewall_df) > 0:
            vpcs_and_fw = gateways_df.merge(
                firewall_df, left_on="vpc_name", right_on="gw_name", how="left"
            )
        else:
            vpcs_and_fw = gateways_df.copy()
            vpcs_and_fw["base_policy"] = np.nan

        # Sort by VPCs with known policies, then remove duplicate VPCs
        vpcs_and_fw = vpcs_and_fw.sort_values(["base_policy"]).drop_duplicates(
            subset=["vpc_id"], keep="first"
        )
        vpcs_and_fw["base_policy"] = vpcs_and_fw["base_policy"].fillna("unknown")

        # Prepare SmartGroup column naming
        vpcs_and_fw["smart_groups"] = vpcs_and_fw["vpc_id"]

        # Use DataCleaner for consistent VPC name cleaning (same as SmartGroup creation)
        vpcs_and_fw["smart_groups"] = self.cleaner.pretty_parse_vpc_name(vpcs_and_fw, "smart_groups")

        vpcs_and_fw["smart_groups"] = vpcs_and_fw["smart_groups"].apply(
            lambda x: self.create_smartgroup_reference(x)
        )

        vpcs_and_fw = vpcs_and_fw.groupby(["base_policy"])["smart_groups"].apply(list).reset_index()

        vpcs_and_fw["src_smart_groups"] = vpcs_and_fw["smart_groups"]
        vpcs_and_fw["dst_smart_groups"] = vpcs_and_fw["smart_groups"]
        vpcs_and_fw["action"] = vpcs_and_fw["base_policy"].map(
            {"deny-all": "DENY", "allow-all": "PERMIT", "unknown": "PERMIT"}
        )

        vpcs_and_fw = vpcs_and_fw[["src_smart_groups", "dst_smart_groups", "base_policy", "action"]]

        # Build different catch-all policy types
        policy_dataframes = []

        # Deny rules
        deny_policies = self._build_deny_policies(vpcs_and_fw)
        if len(deny_policies) > 0:
            policy_dataframes.extend(deny_policies)

        # Allow rules
        allow_policies = self._build_allow_policies(vpcs_and_fw)
        if len(allow_policies) > 0:
            policy_dataframes.extend(allow_policies)

        # Unknown rules
        unknown_policies = self._build_unknown_policies(vpcs_and_fw)
        if len(unknown_policies) > 0:
            policy_dataframes.extend(unknown_policies)

        # Global catch-all
        global_catch_all = self._build_global_catch_all()
        policy_dataframes.append(global_catch_all)

        # Merge all catch-all policies
        catch_all_policies = pd.concat(policy_dataframes, ignore_index=True)
        catch_all_policies["web_groups"] = None
        catch_all_policies["port_ranges"] = None
        catch_all_policies["protocol"] = "ANY"
        catch_all_policies["logging"] = True
        catch_all_policies = catch_all_policies.reset_index(drop=True)

        # Add priorities (catch-all policies start at 3000)
        catch_all_policies.index = catch_all_policies.index + 3000
        catch_all_policies["priority"] = catch_all_policies.index

        if "base_policy" in catch_all_policies.columns:
            catch_all_policies = catch_all_policies.drop("base_policy", axis=1)

        logging.info(f"Created {len(catch_all_policies)} catch-all policies")
        return catch_all_policies

    def _build_deny_policies(self, vpcs_and_fw: pd.DataFrame) -> List[pd.DataFrame]:
        """Build deny catch-all policies."""
        deny_pols = vpcs_and_fw[vpcs_and_fw["base_policy"] == "deny-all"]
        if len(deny_pols) == 0:
            return []

        deny_src_pols = deny_pols.copy()
        deny_src_pols["name"] = "CATCH_ALL_LEGACY_DENY_VPCS_SRC"
        deny_src_pols["dst_smart_groups"] = deny_src_pols["dst_smart_groups"].apply(
            lambda x: [self.anywhere_sg_id]
        )

        deny_dst_pols = deny_pols.copy()
        deny_dst_pols["name"] = "CATCH_ALL_LEGACY_DENY_VPCS_DST"
        deny_dst_pols["src_smart_groups"] = deny_dst_pols["src_smart_groups"].apply(
            lambda x: [self.anywhere_sg_id]
        )

        return [deny_src_pols, deny_dst_pols]

    def _build_allow_policies(self, vpcs_and_fw: pd.DataFrame) -> List[pd.DataFrame]:
        """Build allow catch-all policies."""
        allow_pols = vpcs_and_fw[vpcs_and_fw["base_policy"] == "allow-all"]
        if len(allow_pols) == 0:
            return []

        allow_src_pols = allow_pols.copy()
        allow_src_pols["name"] = "CATCH_ALL_LEGACY_ALLOW_VPCS_SRC"
        allow_src_pols["dst_smart_groups"] = allow_src_pols["dst_smart_groups"].apply(
            lambda x: [self.anywhere_sg_id]
        )

        allow_dst_pols = allow_pols.copy()
        allow_dst_pols["name"] = "CATCH_ALL_LEGACY_ALLOW_VPCS_DST"
        allow_dst_pols["src_smart_groups"] = allow_dst_pols["src_smart_groups"].apply(
            lambda x: [self.anywhere_sg_id]
        )

        return [allow_src_pols, allow_dst_pols]

    def _build_unknown_policies(self, vpcs_and_fw: pd.DataFrame) -> List[pd.DataFrame]:
        """Build unknown VPC catch-all policies."""
        unknown_pols = vpcs_and_fw[vpcs_and_fw["base_policy"] == "unknown"]
        if len(unknown_pols) == 0:
            return []

        unknown_src_pols = unknown_pols.copy()
        unknown_src_pols["name"] = "CATCH_ALL_LEGACY_UNKNOWN_VPCS_SRC"
        unknown_src_pols["dst_smart_groups"] = unknown_src_pols["dst_smart_groups"].apply(
            lambda x: [self.anywhere_sg_id]
        )

        unknown_dst_pols = unknown_pols.copy()
        unknown_dst_pols["name"] = "CATCH_ALL_LEGACY_UNKNOWN_VPCS_DST"
        unknown_dst_pols["src_smart_groups"] = unknown_dst_pols["src_smart_groups"].apply(
            lambda x: [self.anywhere_sg_id]
        )

        return [unknown_src_pols, unknown_dst_pols]

    def _build_global_catch_all(self) -> pd.DataFrame:
        """Build global catch-all policy."""
        return pd.DataFrame(
            [
                {
                    "src_smart_groups": [self.anywhere_sg_id],
                    "dst_smart_groups": [self.anywhere_sg_id],
                    "action": self.global_catch_all_action,
                    "logging": False,
                    "protocol": "ANY",
                    "name": "GLOBAL_CATCH_ALL",
                    "port_ranges": None,
                    "web_groups": None,
                }
            ]
        )


class HostnamePolicyBuilder(PolicyBuilder):
    """Builds policies using hostname SmartGroups for non-web FQDN traffic."""

    def __init__(self, internet_sg_id: str, anywhere_sg_id: str):
        super().__init__(internet_sg_id, anywhere_sg_id)
        self.cleaner = DataCleaner(TranslationConfig())

    def build_hostname_policies(
        self,
        gateways_df: pd.DataFrame,
        fqdn_df: pd.DataFrame,
        hostname_smartgroups_df: pd.DataFrame,
        hostname_rules_df: pd.DataFrame,
    ) -> pd.DataFrame:
        """
        Build L4 policies using hostname SmartGroups as destinations.

        Args:
            gateways_df: DataFrame with gateway details
            fqdn_df: DataFrame with FQDN configurations
            hostname_smartgroups_df: DataFrame with hostname SmartGroups
            hostname_rules_df: DataFrame with hostname FQDN rules

        Returns:
            DataFrame with hostname-based policies
        """
        if len(hostname_smartgroups_df) == 0 or len(hostname_rules_df) == 0:
            logging.info("No hostname SmartGroups or rules to process")
            return pd.DataFrame()

        logging.info(f"Building hostname policies from {len(hostname_smartgroups_df)} SmartGroups")

        # Get egress VPCs (same logic as in build_internet_policies)
        egress_vpcs = gateways_df[
            (gateways_df["is_hagw"] == "no") & (gateways_df["egress_control"] == "Enabled")
        ].drop_duplicates(subset=["vpc_id", "vpc_region", "account_name"])

        if len(egress_vpcs) == 0:
            logging.info("No egress VPCs found")
            return pd.DataFrame()

        egress_vpcs = egress_vpcs[["fqdn_tags", "vpc_name", "vpc_id"]]
        egress_vpcs["src_smart_groups"] = egress_vpcs["vpc_id"]

        # Clean VPC names for SmartGroup references
        egress_vpcs["src_smart_groups"] = self.cleaner.pretty_parse_vpc_name(egress_vpcs, "src_smart_groups")

        # Clean up disabled tag references
        disabled_tag_names = list(fqdn_df[~fqdn_df["fqdn_enabled"]]["fqdn_tag"])
        egress_vpcs["fqdn_tags"] = egress_vpcs["fqdn_tags"].apply(
            lambda x: [item for item in x if item not in disabled_tag_names]
        )

        # Find VPCs that have FQDN tags that would map to hostname smartgroups
        egress_vpcs_with_hostname_tags = egress_vpcs.explode("fqdn_tags").rename(
            columns={"fqdn_tags": "fqdn_tag"}
        )
        egress_vpcs_with_hostname_tags = egress_vpcs_with_hostname_tags.merge(
            fqdn_df, on="fqdn_tag", how="left"
        )
        egress_vpcs_with_hostname_tags = egress_vpcs_with_hostname_tags[
            egress_vpcs_with_hostname_tags["fqdn_enabled"].fillna(False)
        ]
        egress_vpcs_with_hostname_tags = egress_vpcs_with_hostname_tags.rename(
            columns={"fqdn_tag": "fqdn_tag_name"}
        )

        # Match VPCs to hostname rules to determine which hostname smartgroups they should use
        vpc_hostname_matches = egress_vpcs_with_hostname_tags.merge(
            hostname_rules_df[["fqdn_tag_name", "protocol", "port", "fqdn_mode", "fqdn"]],
            on=["fqdn_tag_name", "fqdn_mode"],
            how="inner",
        )

        # Create policies for each VPC/hostname SmartGroup combination
        hostname_policies = []
        for _, sg_row in hostname_smartgroups_df.iterrows():
            protocol = sg_row["protocol"]
            port = sg_row["port"]
            fqdn_mode = sg_row["fqdn_mode"]
            sg_name = sg_row["name"]
            sg_fqdn_list = sg_row["fqdn_list"]

            # Find VPCs that should use this hostname smartgroup
            matching_vpcs = vpc_hostname_matches[
                (vpc_hostname_matches["protocol"] == protocol)
                & (vpc_hostname_matches["port"] == port)
                & (vpc_hostname_matches["fqdn_mode"] == fqdn_mode)
                & (vpc_hostname_matches["fqdn"].isin(sg_fqdn_list))
            ].drop_duplicates(subset=["src_smart_groups"])

            if len(matching_vpcs) > 0:
                # Group by VPC to create one policy per VPC for this hostname smartgroup
                for vpc_name, _vpc_group in matching_vpcs.groupby(["src_smart_groups", "vpc_name"]):
                    src_sg_name, vpc_display_name = vpc_name
                    src_sg_ref = self.create_smartgroup_reference(src_sg_name)
                    dst_sg_ref = self.create_smartgroup_reference(sg_name)

                    action = "PERMIT" if fqdn_mode == "white" else "DENY"
                    policy_name = (
                        f"FQDN_{vpc_display_name}_{'permit' if fqdn_mode == 'white' else 'deny'}"
                    )

                    # Convert port to port_ranges format, handling special cases
                    if port == "ALL":
                        port_ranges = None  # No port restrictions for ALL
                    else:
                        port_ranges = translate_port_to_port_range([port]) if port else None

                    # Ensure protocol is properly formatted for DCF
                    dcf_protocol = normalize_protocol(protocol)

                    hostname_policies.append(
                        {
                            "src_smart_groups": [src_sg_ref],
                            "dst_smart_groups": [dst_sg_ref],
                            "action": action,
                            "logging": True,
                            "protocol": dcf_protocol,
                            "name": policy_name,
                            "port_ranges": port_ranges,
                            "web_groups": None,
                        }
                    )

        hostname_policies_df = pd.DataFrame(hostname_policies)
        if len(hostname_policies_df) > 0:
            hostname_policies_df = self.cleaner.remove_invalid_name_chars(
                hostname_policies_df, "name"
            )
            # Deduplicate policy names
            hostname_policies_df = self._deduplicate_policy_names(hostname_policies_df)

        logging.info(f"Created {len(hostname_policies_df)} VPC-level hostname policies")
        return hostname_policies_df


class L4PolicyHandler:
    """Handler for L4 policy translation operations."""

    def __init__(self, config: Any) -> None:
        """Initialize the L4 policy handler with configuration."""
        self.config = config
        self.policy_builder = L4PolicyBuilder(
            internet_sg_id=config.internet_sg_id, anywhere_sg_id=config.anywhere_sg_id
        )

    def build_l4_policies(self, fw_policy_df: pd.DataFrame) -> pd.DataFrame:
        """Build L4 DCF policies from legacy firewall policies."""
        return self.policy_builder.build_l4_policies(fw_policy_df)


# Legacy function wrappers for backward compatibility
def build_l4_dcf_policies(
    fw_policy_df: pd.DataFrame, internet_sg_id: str = "", anywhere_sg_id: str = ""
) -> pd.DataFrame:
    """Legacy wrapper for building L4 DCF policies."""
    builder = L4PolicyBuilder(internet_sg_id, anywhere_sg_id)
    return builder.build_l4_policies(fw_policy_df)


def build_internet_policies(
    gateways_df: pd.DataFrame,
    fqdn_df: pd.DataFrame,
    webgroups_df: pd.DataFrame,
    any_webgroup_id: str,
    internet_sg_id: str = "",
    anywhere_sg_id: str = "",
    default_web_port_ranges: Optional[List[str]] = None,
    hostname_smartgroups_df: pd.DataFrame = None,
    hostname_rules_df: pd.DataFrame = None,
) -> pd.DataFrame:
    """Legacy wrapper for building internet policies (webgroup and hostname-based)."""
    if default_web_port_ranges is None:
        default_web_port_ranges = ["80", "443"]

    builder = InternetPolicyBuilder(
        internet_sg_id, anywhere_sg_id, default_web_port_ranges, any_webgroup_id
    )
    return builder.build_internet_policies(
        gateways_df, fqdn_df, webgroups_df, hostname_smartgroups_df, hostname_rules_df
    )


def build_webgroup_policies(
    gateways_df: pd.DataFrame,
    fqdn_df: pd.DataFrame,
    webgroups_df: pd.DataFrame,
    any_webgroup_id: str,
    internet_sg_id: str = "",
    anywhere_sg_id: str = "",
    default_web_port_ranges: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Wrapper for building webgroup policies only."""
    if default_web_port_ranges is None:
        default_web_port_ranges = ["80", "443"]

    builder = InternetPolicyBuilder(
        internet_sg_id, anywhere_sg_id, default_web_port_ranges, any_webgroup_id
    )
    return builder.build_webgroup_policies(gateways_df, fqdn_df, webgroups_df)


def build_hostname_policies_only(
    gateways_df: pd.DataFrame,
    fqdn_df: pd.DataFrame,
    hostname_smartgroups_df: pd.DataFrame,
    hostname_rules_df: pd.DataFrame,
    internet_sg_id: str = "",
    anywhere_sg_id: str = "",
    default_web_port_ranges: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Wrapper for building hostname policies only."""
    if default_web_port_ranges is None:
        default_web_port_ranges = ["80", "443"]

    builder = InternetPolicyBuilder(
        internet_sg_id, anywhere_sg_id, default_web_port_ranges, ""
    )
    return builder.build_hostname_policies(gateways_df, fqdn_df, hostname_smartgroups_df, hostname_rules_df)


def build_catch_all_policies(
    gateways_df: pd.DataFrame,
    firewall_df: pd.DataFrame,
    internet_sg_id: str = "",
    anywhere_sg_id: str = "",
    global_catch_all_action: str = "PERMIT",
) -> pd.DataFrame:
    """Legacy wrapper for building catch-all policies."""
    builder = CatchAllPolicyBuilder(internet_sg_id, anywhere_sg_id, global_catch_all_action)
    return builder.build_catch_all_policies(gateways_df, firewall_df)


def build_hostname_policies(
    gateways_df: pd.DataFrame,
    fqdn_df: pd.DataFrame,
    hostname_smartgroups_df: pd.DataFrame,
    hostname_rules_df: pd.DataFrame,
    internet_sg_id: str = "",
    anywhere_sg_id: str = "",
) -> pd.DataFrame:
    """Legacy wrapper for building hostname policies."""
    builder = HostnamePolicyBuilder(internet_sg_id, anywhere_sg_id)
    return builder.build_hostname_policies(
        gateways_df, fqdn_df, hostname_smartgroups_df, hostname_rules_df
    )
