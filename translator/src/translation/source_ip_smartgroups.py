"""
Source IP List SmartGroup Manager

This module handles the creation of SmartGroups for FQDN source IP lists, supporting
both simple CIDR-based and advanced asset-based translation modes.

Key Components:
- SourceIPSmartGroupManager: Main class for managing source IP SmartGroups
- Simple mode: Creates CIDR-based SmartGroups directly from source IP lists
- Advanced mode: Creates asset-based SmartGroups using CoPilot discovery data
- Collision detection and naming strategy for SmartGroup resources
"""

import logging
from typing import Any, Dict, List, Optional, Set

import pandas as pd
from config import TranslationConfig
from data.copilot_loader import AssetMatcher
from data.processors import DataCleaner


class SourceIPSmartGroupManager:
    """Manages creation of SmartGroups for FQDN source IP filtering."""

    def __init__(self, config: TranslationConfig, asset_matcher: Optional[AssetMatcher] = None):
        """
        Initialize SourceIPSmartGroupManager.

        Args:
            config: Translation configuration
            asset_matcher: Optional AssetMatcher for advanced translation mode
        """
        self.config = config
        self.asset_matcher = asset_matcher
        self.data_cleaner = DataCleaner(config)
        self.logger = logging.getLogger(__name__)

        # Track created SmartGroups to avoid duplicates
        self.created_smartgroups: Set[str] = set()
        self.smartgroup_registry: Dict[str, Dict[str, Any]] = {}

    def _clean_name(self, name: str) -> str:
        """Clean a name for DCF compatibility."""
        # Create a temporary DataFrame to use the cleaner
        temp_df = pd.DataFrame({"name": [name]})
        cleaned_df = self.data_cleaner.remove_invalid_name_chars(temp_df, "name")
        return str(cleaned_df["name"].iloc[0])

    def process_fqdn_source_ip_lists(self, fqdn_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Process FQDN data to create source IP list SmartGroups.

        Args:
            fqdn_df: DataFrame containing FQDN configuration data

        Returns:
            List of SmartGroup definitions for source IP filtering
        """
        source_ip_smartgroups = []

        # Filter FQDN tags that have source IP filters
        filtered_fqdns = fqdn_df[fqdn_df["has_source_ip_filter"]].copy()

        if filtered_fqdns.empty:
            self.logger.info("No FQDN tags with source IP filters found")
            return []

        self.logger.info(f"Processing {len(filtered_fqdns)} FQDN tags with source IP filters")

        for _, fqdn_row in filtered_fqdns.iterrows():
            smartgroups = self._process_single_fqdn_source_ips(fqdn_row)
            source_ip_smartgroups.extend(smartgroups)

        self.logger.info(f"Created {len(source_ip_smartgroups)} source IP SmartGroups")
        return source_ip_smartgroups

    def _process_single_fqdn_source_ips(self, fqdn_row: pd.Series) -> List[Dict[str, Any]]:
        """
        Process a single FQDN tag's source IP lists.

        Args:
            fqdn_row: Single row from FQDN DataFrame

        Returns:
            List of SmartGroup definitions for this FQDN tag
        """
        fqdn_tag = fqdn_row["fqdn_tag"]
        import ast
        source_ip_lists = ast.literal_eval(fqdn_row["source_ip_lists_json"])  # Convert JSON string back to list

        if not source_ip_lists:
            return []

        # Check if we should use advanced translation
        use_advanced = (
            self.config.get_fqdn_source_ip_advanced_translation() and
            self.asset_matcher is not None
        )

        # Collect all source IPs from all gateway assignments
        all_source_ips = []
        for source_ip_entry in source_ip_lists:
            all_source_ips.extend(source_ip_entry["source_ips"])

        if use_advanced:
            return self._create_advanced_smartgroups(fqdn_tag, all_source_ips)
        else:
            return self._create_simple_smartgroups(fqdn_tag, all_source_ips)

    def _create_simple_smartgroups(self, fqdn_tag: str, source_ips: List[str]) -> List[Dict[str, Any]]:
        """
        Create simple CIDR-based SmartGroups for source IP filtering.

        Args:
            fqdn_tag: Name of the FQDN tag
            source_ips: List of source IP addresses/CIDRs

        Returns:
            List containing a single SmartGroup definition
        """
        # Clean the FQDN tag name for SmartGroup naming
        cleaned_tag_name = self._clean_name(fqdn_tag)

        # Use the cleaned tag name directly without any suffix
        smartgroup_name = cleaned_tag_name

        # Ensure unique naming
        smartgroup_name = self._ensure_unique_name(smartgroup_name)

        # Create match expressions for each source IP
        match_expressions = []
        for source_ip in source_ips:
            # Validate and normalize the CIDR
            normalized_cidr = self._normalize_cidr(source_ip)
            if normalized_cidr:
                match_expressions.append({"cidr": normalized_cidr})

        if not match_expressions:
            self.logger.warning(f"No valid source IPs found for FQDN tag: {fqdn_tag}")
            return []

        smartgroup_def = {
            "name": smartgroup_name,
            "selector": {
                "match_expressions": match_expressions
            },
            "source_type": "fqdn_source_ip_simple",
            "fqdn_tag": fqdn_tag,
            "source_ips": source_ips,
        }

        # Register the SmartGroup
        self._register_smartgroup(smartgroup_name, smartgroup_def)

        self.logger.info(f"Created simple source IP SmartGroup: {smartgroup_name} for tag: {fqdn_tag}")
        return [smartgroup_def]

    def _create_advanced_smartgroups(self, fqdn_tag: str, source_ips: List[str]) -> List[Dict[str, Any]]:
        """
        Create advanced asset-based SmartGroups for source IP filtering.

        Args:
            fqdn_tag: Name of the FQDN tag
            source_ips: List of source IP addresses/CIDRs

        Returns:
            List of SmartGroup definitions (asset-based or fallback to simple)
        """
        if not self.asset_matcher:
            self.logger.warning("Asset matcher not available, falling back to simple mode")
            return self._create_simple_smartgroups(fqdn_tag, source_ips)

        # Get asset matching summary
        match_summary = self.asset_matcher.get_matching_assets_summary(source_ips)

        asset_smartgroups = []
        unmatched_ips = match_summary["unmatched_ips"]

        # Create asset-based SmartGroups for matched IPs
        asset_groups = self._group_matches_by_asset(match_summary["matches"])

        for asset_key, asset_matches in asset_groups.items():
            smartgroup_def = self._create_asset_smartgroup(fqdn_tag, asset_key, asset_matches)
            if smartgroup_def:
                asset_smartgroups.append(smartgroup_def)

        # Create simple SmartGroup for unmatched IPs if any
        if unmatched_ips:
            self.logger.info(f"Creating fallback SmartGroup for {len(unmatched_ips)} unmatched IPs")
            fallback_smartgroups = self._create_simple_smartgroups(f"{fqdn_tag}_unmatched", unmatched_ips)
            asset_smartgroups.extend(fallback_smartgroups)

        if not asset_smartgroups:
            self.logger.warning(f"No asset matches found for FQDN tag: {fqdn_tag}, falling back to simple mode")
            return self._create_simple_smartgroups(fqdn_tag, source_ips)

        self.logger.info(f"Created {len(asset_smartgroups)} advanced SmartGroups for tag: {fqdn_tag}")
        return asset_smartgroups

    def _group_matches_by_asset(self, matches: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group asset matches by unique asset identity.

        Args:
            matches: List of asset match dictionaries

        Returns:
            Dictionary mapping asset keys to lists of matches
        """
        asset_groups: Dict[str, List[Dict[str, Any]]] = {}

        for match in matches:
            asset_name = match.get("asset_name", "")
            account_name = match.get("account_name", "")
            asset_type = match.get("asset_type", "vm")
            asset_id = match.get("asset_id", "")

            # Handle empty asset names by using asset_id or IP as fallback
            if not asset_name or asset_name.strip() == "":
                if asset_id:
                    asset_name = asset_id
                else:
                    # Use source IP as last resort
                    asset_name = match.get("source_ip", "unknown")

            # Create a unique key for the asset (include type to ensure different asset types are separate)
            asset_key = f"{asset_name}_{account_name}_{asset_type}"

            if asset_key not in asset_groups:
                asset_groups[asset_key] = []

            asset_groups[asset_key].append(match)

        return asset_groups

    def _create_asset_smartgroup(self, fqdn_tag: str, asset_key: str, asset_matches: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Create an asset-based SmartGroup definition.

        Args:
            fqdn_tag: FQDN tag name to use for SmartGroup naming
            asset_key: Unique key for the asset group
            asset_matches: List of asset matches for this group

        Returns:
            SmartGroup definition or None if invalid
        """
        if not asset_matches:
            return None

        # Get asset information from the first match (all should be the same asset)
        first_match = asset_matches[0]
        asset_name = first_match.get("asset_name", "")
        account_name = first_match.get("account_name", "")
        asset_type = first_match.get("asset_type", "vm")
        ips_or_cidrs = first_match.get("ips_or_cidrs", [])

        # Handle fallback naming when asset_name is empty or None
        if not asset_name or asset_name.strip() == "":
            # Use the first CIDR as fallback name if asset name is missing
            if ips_or_cidrs:
                asset_name = ips_or_cidrs[0].replace("/", "_").replace(".", "_")
            else:
                # Last resort: use the source IP from the match
                asset_name = first_match.get("source_ip", "unknown").replace("/", "_").replace(".", "_")

        # Use the FQDN tag name directly for consistent naming
        cleaned_tag_name = self._clean_name(fqdn_tag)
        smartgroup_name = cleaned_tag_name

        # Ensure unique naming
        smartgroup_name = self._ensure_unique_name(smartgroup_name)

        # Create the match expression based on asset type
        match_expression = self._create_match_expression_for_asset_type(
            asset_type, asset_name, account_name
        )

        smartgroup_def = {
            "name": smartgroup_name,
            "selector": {
                "match_expressions": [match_expression]
            },
            "source_type": "fqdn_source_ip_asset",
            "fqdn_tag": fqdn_tag,
            "asset_name": asset_name,
            "asset_type": asset_type,
            "account_name": account_name,
            "matched_ips": [match["source_ip"] for match in asset_matches],
        }

        # Register the SmartGroup
        self._register_smartgroup(smartgroup_name, smartgroup_def)

        self.logger.info(f"Created asset-based SmartGroup: {smartgroup_name} (type: {asset_type}) for FQDN tag: {fqdn_tag}")
        return smartgroup_def

    def _create_match_expression_for_asset_type(self, asset_type: str, asset_name: str, account_name: str) -> Dict[str, Any]:
        """
        Create a match expression based on the asset type.

        Args:
            asset_type: Type of asset (vm, subnet, vpc, etc.)
            asset_name: Name of the asset
            account_name: Account name

        Returns:
            Match expression dictionary
        """
        # Base expression with common fields
        match_expression = {
            "type": asset_type,
            "account_name": account_name,
        }

        # Add name field only if asset_name is not empty
        if asset_name and asset_name.strip():
            match_expression["name"] = asset_name

        return match_expression

    def _normalize_cidr(self, ip_or_cidr: str) -> Optional[str]:
        """
        Normalize and validate a CIDR or IP address.

        Args:
            ip_or_cidr: IP address or CIDR to normalize

        Returns:
            Normalized CIDR string or None if invalid
        """
        try:
            from ipaddress import ip_network

            # Parse and normalize the CIDR/IP
            network = ip_network(ip_or_cidr, strict=False)
            return str(network)

        except Exception as e:
            self.logger.warning(f"Invalid IP/CIDR: {ip_or_cidr} - {e}")
            return None

    def _ensure_unique_name(self, base_name: str) -> str:
        """
        Ensure SmartGroup name is unique by adding suffix if needed.

        Args:
            base_name: Base name for the SmartGroup

        Returns:
            Unique SmartGroup name
        """
        if base_name not in self.created_smartgroups:
            self.created_smartgroups.add(base_name)
            return base_name

        counter = 1
        while True:
            unique_name = f"{base_name}_{counter}"
            if unique_name not in self.created_smartgroups:
                self.created_smartgroups.add(unique_name)
                return unique_name
            counter += 1

    def _register_smartgroup(self, name: str, definition: Dict[str, Any]) -> None:
        """
        Register a SmartGroup in the internal registry.

        Args:
            name: SmartGroup name
            definition: SmartGroup definition
        """
        self.smartgroup_registry[name] = definition

    def get_smartgroup_registry(self) -> Dict[str, Dict[str, Any]]:
        """
        Get the registry of all created SmartGroups.

        Returns:
            Dictionary mapping SmartGroup names to their definitions
        """
        return self.smartgroup_registry.copy()

    def get_source_ip_smartgroup_reference(self, fqdn_tag: str) -> Optional[str]:
        """
        Get the Terraform reference for a source IP SmartGroup by FQDN tag.

        Args:
            fqdn_tag: FQDN tag name

        Returns:
            Terraform reference string or None if not found
        """
        # Find SmartGroups that match this FQDN tag
        for sg_name, sg_def in self.smartgroup_registry.items():
            if sg_def.get("fqdn_tag") == fqdn_tag:
                return f"${{aviatrix_smart_group.{sg_name}.id}}"

        return None
