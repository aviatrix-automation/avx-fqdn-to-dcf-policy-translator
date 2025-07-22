"""
SmartGroup creation and management module for the legacy-to-DCF policy translator.

Handles the creation of CIDR-based, VPC-based, and hostname-based SmartGroups.
"""

import ipaddress
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd

sys.path.append(str(Path(__file__).parent.parent))
from config import TranslationConfig
from data.processors import DataCleaner
from translation.source_ip_smartgroups import SourceIPSmartGroupManager


class SmartGroupBuilder:
    """Builds SmartGroups from various sources (firewall tags, CIDRs, VPCs, hostnames)."""

    def __init__(self, config: TranslationConfig):
        self.config = config
        self.cleaner = DataCleaner(config)
        self.logger = logging.getLogger(__name__)

    def translate_fw_tag_to_sg_selector(self, tag_cidrs: Any) -> Dict[str, Any]:
        """
        Convert firewall tag CIDR list to SmartGroup selector format.

        Args:
            tag_cidrs: CIDR data (dict, list, or None)

        Returns:
            SmartGroup selector dictionary
        """
        match_expressions: Any
        if isinstance(tag_cidrs, dict):
            match_expressions = {"cidr": tag_cidrs["cidr"]}
        elif isinstance(tag_cidrs, list):
            match_expressions = []
            for cidr in tag_cidrs:
                match_expressions.append({"cidr": cidr["cidr"]})
        else:
            match_expressions = None

        return {"match_expressions": match_expressions}

    def build_firewall_tag_smartgroups(self, fw_tag_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build SmartGroups from firewall tags.

        Args:
            fw_tag_df: DataFrame containing firewall tag data

        Returns:
            DataFrame containing SmartGroup definitions
        """
        if fw_tag_df.empty:
            return pd.DataFrame(columns=["name", "selector"])

        tag_df = fw_tag_df.copy()
        tag_df["selector"] = tag_df["cidr_list"].apply(self.translate_fw_tag_to_sg_selector)
        tag_df = tag_df.rename(columns={"firewall_tag": "name"})
        tag_df = tag_df[["name", "selector"]]

        self.logger.info(f"Created {len(tag_df)} SmartGroups from firewall tags")
        return tag_df

    def build_cidr_smartgroups(
        self, fw_policy_df: pd.DataFrame, fw_tag_df: pd.DataFrame
    ) -> pd.DataFrame:
        """
        Build SmartGroups for direct CIDR references in policies.

        Args:
            fw_policy_df: DataFrame containing firewall policies
            fw_tag_df: DataFrame containing firewall tags (to exclude existing tags)

        Returns:
            DataFrame containing CIDR-based SmartGroups
        """
        if fw_policy_df.empty:
            return pd.DataFrame(columns=["name", "selector"])

        # Get all CIDRs referenced in policies
        cidrs = pd.concat([fw_policy_df["src_ip"], fw_policy_df["dst_ip"]]).unique()

        # Exclude CIDRs that are already covered by firewall tags
        existing_tag_names = set(fw_tag_df["firewall_tag"]) if not fw_tag_df.empty else set()
        cidrs = set(cidrs) - existing_tag_names

        # Filter to only actual IP addresses/CIDRs
        actual_cidrs = [cidr for cidr in cidrs if self._is_valid_cidr(cidr)]

        # Create SmartGroup entries for each CIDR
        cidr_sgs = []
        for cidr in actual_cidrs:
            cidr_sgs.append(
                {"selector": {"match_expressions": {"cidr": cidr}}, "name": f"cidr_{cidr}"}
            )

        cidr_sg_df = pd.DataFrame(cidr_sgs)
        self.logger.info(f"Created {len(cidr_sg_df)} SmartGroups from direct CIDR references")
        return cidr_sg_df

    def build_vpc_smartgroups(self, gateways_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build SmartGroups for VPCs.

        Args:
            gateways_df: DataFrame containing gateway/VPC data

        Returns:
            DataFrame containing VPC-based SmartGroups
        """
        if gateways_df.empty:
            return pd.DataFrame(columns=["name", "selector"])

        # Get unique VPCs
        vpcs = gateways_df.drop_duplicates(subset=["vpc_id", "vpc_region", "account_name"]).copy()

        # Use the full vpc_id with invalid characters cleaned for SmartGroup name
        vpcs["vpc_name_attr"] = self.cleaner.pretty_parse_vpc_name(vpcs, "vpc_id")

        # Extract the actual VPC name from vpc_id (format: vpc-{id}~~{vpc_name})
        def extract_vpc_name(vpc_id: str) -> str:
            if "~~" in vpc_id:
                return vpc_id.split("~~")[1]  # Get the part after ~~
            else:
                # Fallback: if no ~~, use the cleaned full vpc_id
                return self.cleaner.pretty_parse_vpc_name(pd.DataFrame({"vpc_id": [vpc_id]}), "vpc_id").iloc[0]
        
        vpcs["actual_vpc_name"] = vpcs["vpc_id"].apply(extract_vpc_name)

        # Create selectors for VPC matching
        vpcs["selector"] = vpcs.apply(
            lambda row: {
                "match_expressions": {
                    "name": row["actual_vpc_name"],  # Use actual VPC name
                    "region": row["vpc_region"],
                    "account_name": row["account_name"],
                    "type": "vpc",
                }
            },
            axis=1,
        )

        # Use the cleaned vpc_id as the SmartGroup name
        vpcs = vpcs.rename(columns={"vpc_name_attr": "name"})
        vpcs = vpcs[["name", "selector"]]

        self.logger.info(f"Created {len(vpcs)} SmartGroups from VPCs")
        return vpcs

    def build_hostname_smartgroups(self, hostname_rules_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build hostname-based SmartGroups for FQDN rules that don't use webgroups.

        Args:
            hostname_rules_df: DataFrame containing hostname rules

        Returns:
            DataFrame containing hostname SmartGroups
        """
        if hostname_rules_df.empty:
            return pd.DataFrame(
                columns=["name", "selector", "protocol", "port", "fqdn_mode", "fqdn_list"]
            )

        # Group FQDNs by protocol, port, fqdn_mode, and fqdn_tag_name for optimization
        grouped = (
            hostname_rules_df.groupby(["fqdn_tag_name", "protocol", "port", "fqdn_mode"])["fqdn"]
            .apply(list)
            .reset_index()
        )

        hostname_smartgroups = []
        for _, row in grouped.iterrows():
            # Create a unique name for the hostname smartgroup
            # Note: protocol and port variables removed as they were unused
            mode = row["fqdn_mode"]
            fqdn_tag_name = row["fqdn_tag_name"]

            # Create a hash for uniqueness when there are many FQDNs
            fqdn_list = row["fqdn"]
            fqdn_hash = abs(hash(str(sorted(fqdn_list)))) % 10000

            name = f"fqdn_{fqdn_tag_name}_{fqdn_hash}"

            # Create selector for hostname smartgroup using fqdn field
            # Always use a list of match expressions for consistency
            match_expressions = []
            for fqdn in fqdn_list:
                match_expressions.append({"fqdn": fqdn.strip()})
            selector = {"match_expressions": match_expressions}

            hostname_smartgroups.append(
                {
                    "name": name,
                    "selector": selector,
                    "protocol": row["protocol"],  # Store original protocol value (ANY, etc.)
                    "port": row["port"],  # Store original port value (ALL, etc.)
                    "fqdn_mode": mode,
                    "fqdn_list": fqdn_list,
                }
            )

        hostname_sg_df = pd.DataFrame(hostname_smartgroups)
        hostname_sg_df = self.cleaner.remove_invalid_name_chars(hostname_sg_df, "name")

        # Remove duplicates based on SmartGroup name
        initial_count = len(hostname_sg_df)
        hostname_sg_df = hostname_sg_df.drop_duplicates(subset=["name"], keep="first")
        duplicate_count = initial_count - len(hostname_sg_df)
        
        if duplicate_count > 0:
            self.logger.warning(
                f"Removed {duplicate_count} duplicate hostname SmartGroups "
                f"(hash collisions in name generation)"
            )

        self.logger.info(f"Created {len(hostname_sg_df)} hostname SmartGroups")
        return hostname_sg_df

    def build_smartgroup_df(
        self, fw_policy_df: pd.DataFrame, fw_tag_df: pd.DataFrame, gateways_df: pd.DataFrame
    ) -> pd.DataFrame:
        """
        Build complete SmartGroup DataFrame from all sources.

        Args:
            fw_policy_df: DataFrame containing firewall policies
            fw_tag_df: DataFrame containing firewall tags
            gateways_df: DataFrame containing gateway data

        Returns:
            DataFrame containing all SmartGroups
        """
        self.logger.info("Building comprehensive SmartGroups from all sources")

        sg_dfs = []

        # Process firewall tags
        if not fw_tag_df.empty:
            fw_tag_sgs = self.build_firewall_tag_smartgroups(fw_tag_df)
            if not fw_tag_sgs.empty:
                sg_dfs.append(fw_tag_sgs)

        # Process direct CIDR references from policies
        if not fw_policy_df.empty:
            cidr_sgs = self.build_cidr_smartgroups(fw_policy_df, fw_tag_df)
            if not cidr_sgs.empty:
                sg_dfs.append(cidr_sgs)

        # Process VPC SmartGroups
        if not gateways_df.empty:
            vpc_sgs = self.build_vpc_smartgroups(gateways_df)
            if not vpc_sgs.empty:
                sg_dfs.append(vpc_sgs)

        # Merge all SmartGroup DataFrames
        if sg_dfs:
            smartgroups = pd.concat(sg_dfs, ignore_index=True)
            # Clean invalid characters in names
            smartgroups = self.cleaner.remove_invalid_name_chars(smartgroups, "name")
            
            # Remove duplicates based on SmartGroup name
            initial_count = len(smartgroups)
            smartgroups = smartgroups.drop_duplicates(subset=["name"], keep="first")
            duplicate_count = initial_count - len(smartgroups)
            
            if duplicate_count > 0:
                self.logger.warning(
                    f"Removed {duplicate_count} duplicate SmartGroups during merge"
                )
        else:
            smartgroups = pd.DataFrame(columns=["name", "selector"])

        self.logger.info(f"Built {len(smartgroups)} total SmartGroups")
        return smartgroups

    def _is_valid_cidr(self, cidr_str: str) -> bool:
        """
        Check if a string represents a valid IPv4 CIDR.

        Args:
            cidr_str: String to validate

        Returns:
            True if valid CIDR, False otherwise
        """
        try:
            ipaddress.IPv4Network(cidr_str, strict=False)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False


class SmartGroupManager:
    """Manages SmartGroup operations and provides high-level interface."""

    def __init__(self, config: TranslationConfig, asset_matcher: Optional[Any] = None):
        self.config = config
        self.builder = SmartGroupBuilder(config)
        self.source_ip_manager = SourceIPSmartGroupManager(config, asset_matcher)
        self.logger = logging.getLogger(__name__)

    def create_all_smartgroups(
        self,
        fw_policy_df: pd.DataFrame,
        fw_tag_df: pd.DataFrame,
        gateways_df: pd.DataFrame,
        hostname_rules_df: Optional[pd.DataFrame] = None,
        fqdn_df: Optional[pd.DataFrame] = None,
    ) -> Dict[str, pd.DataFrame]:
        """
        Create all types of SmartGroups and return organized results.

        Args:
            fw_policy_df: Firewall policies DataFrame
            fw_tag_df: Firewall tags DataFrame
            gateways_df: Gateways DataFrame
            hostname_rules_df: Optional hostname rules DataFrame
            fqdn_df: Optional FQDN DataFrame for source IP SmartGroups

        Returns:
            Dictionary containing different types of SmartGroups
        """
        results = {}

        # Create standard SmartGroups (CIDR-based, VPC-based, tag-based)
        standard_smartgroups = self.builder.build_smartgroup_df(
            fw_policy_df, fw_tag_df, gateways_df
        )
        results["standard_smartgroups"] = standard_smartgroups

        # Create hostname SmartGroups if hostname rules are provided
        if hostname_rules_df is not None and not hostname_rules_df.empty:
            hostname_smartgroups = self.builder.build_hostname_smartgroups(hostname_rules_df)
            results["hostname_smartgroups"] = hostname_smartgroups
        else:
            results["hostname_smartgroups"] = pd.DataFrame(columns=["name", "selector"])

        # Create source IP SmartGroups if FQDN data is provided
        source_ip_smartgroups_list = []
        if fqdn_df is not None and not fqdn_df.empty:
            source_ip_smartgroups_list = self.source_ip_manager.process_fqdn_source_ip_lists(fqdn_df)

            # Convert to DataFrame format for consistency
            if source_ip_smartgroups_list:
                source_ip_sg_df = pd.DataFrame([
                    {"name": sg["name"], "selector": sg["selector"]}
                    for sg in source_ip_smartgroups_list
                ])
                results["source_ip_smartgroups"] = source_ip_sg_df
            else:
                results["source_ip_smartgroups"] = pd.DataFrame(columns=["name", "selector"])
        else:
            results["source_ip_smartgroups"] = pd.DataFrame(columns=["name", "selector"])

        # Merge all SmartGroups for complete list
        smartgroup_dfs = [
            standard_smartgroups,
            results["hostname_smartgroups"][["name", "selector"]] if not results["hostname_smartgroups"].empty else pd.DataFrame(columns=["name", "selector"]),
            results["source_ip_smartgroups"]
        ]

        # Filter out empty DataFrames and concatenate
        non_empty_dfs = [df for df in smartgroup_dfs if not df.empty]
        if non_empty_dfs:
            complete_smartgroups = pd.concat(non_empty_dfs, ignore_index=True)
            
            # Remove duplicates based on SmartGroup name
            initial_count = len(complete_smartgroups)
            complete_smartgroups = complete_smartgroups.drop_duplicates(subset=["name"], keep="first")
            duplicate_count = initial_count - len(complete_smartgroups)
            
            if duplicate_count > 0:
                self.logger.warning(
                    f"Removed {duplicate_count} duplicate SmartGroups from final assembly"
                )
        else:
            complete_smartgroups = pd.DataFrame(columns=["name", "selector"])

        results["complete_smartgroups"] = complete_smartgroups

        # Log summary
        self.logger.info("SmartGroup creation summary:")
        self.logger.info(f"  Standard SmartGroups: {len(results['standard_smartgroups'])}")
        self.logger.info(f"  Hostname SmartGroups: {len(results['hostname_smartgroups'])}")
        self.logger.info(f"  Source IP SmartGroups: {len(results['source_ip_smartgroups'])}")
        self.logger.info(f"  Total SmartGroups: {len(results['complete_smartgroups'])}")

        return results

    def get_source_ip_smartgroup_reference(self, fqdn_tag: str) -> Optional[str]:
        """
        Get the Terraform reference for a source IP SmartGroup by FQDN tag.

        Args:
            fqdn_tag: FQDN tag name

        Returns:
            Terraform reference string or None if not found
        """
        return self.source_ip_manager.get_source_ip_smartgroup_reference(fqdn_tag)  # type: ignore[no-any-return]
