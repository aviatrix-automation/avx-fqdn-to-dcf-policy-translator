"""
CoPilot Asset Loader Module

This module handles loading and processing CoPilot app domains data for advanced
FQDN source IP list translation. It provides functionality to:
- Load and parse copilot_app_domains.json
- Match source IP addresses to discovered assets
- Extract asset metadata for SmartGroup creation

Key Components:
- CoPilotAssetLoader: Main class for loading asset data
- AssetMatcher: Logic for matching IPs to assets
- Asset data validation and processing
"""

import json
import logging
from ipaddress import AddressValueError, ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd


class AssetMatcher:
    """Handles matching IP addresses to CoPilot discovered assets."""

    def __init__(self, assets: List[Dict[str, Any]]):
        """
        Initialize AssetMatcher with asset data.

        Args:
            assets: List of asset dictionaries from CoPilot
        """
        self.assets = assets
        self.logger = logging.getLogger(__name__)
        self._preprocess_assets()

    def _preprocess_assets(self) -> None:
        """Preprocess assets for efficient IP matching."""
        self.ip_to_asset_map: Dict[str, Dict[str, Any]] = {}
        self.network_to_asset_map: List[Tuple[Any, Dict[str, Any]]] = []

        for asset in self.assets:
            ips_or_cidrs = asset.get("ips_or_cidrs", [])

            for ip_or_cidr in ips_or_cidrs:
                try:
                    # Try to parse as a network/CIDR first
                    network = ip_network(ip_or_cidr, strict=False)
                    if network.num_addresses == 1:
                        # It's a single IP address (/32 or /128)
                        self.ip_to_asset_map[str(network.network_address)] = asset
                    else:
                        # It's a network range
                        self.network_to_asset_map.append((network, asset))
                except AddressValueError:
                    self.logger.warning(
                        f"Invalid IP/CIDR in asset {asset.get('name', 'Unknown')}: {ip_or_cidr}"
                    )

    def find_matching_asset(self, source_ip: str) -> Optional[Dict[str, Any]]:
        """
        Find the asset that matches the given source IP.

        Args:
            source_ip: IP address to match (e.g., "21.0.1.41/32" or "21.0.1.41")

        Returns:
            Matching asset dictionary or None if no match found
        """
        try:
            # Remove CIDR notation if present (e.g., "21.0.1.41/32" -> "21.0.1.41")
            ip_str = source_ip.split('/')[0]
            ip = ip_address(ip_str)

            # Check exact IP matches first
            if str(ip) in self.ip_to_asset_map:
                return self.ip_to_asset_map[str(ip)]

            # Check network matches
            for network, asset in self.network_to_asset_map:
                if ip in network:
                    return asset

            return None

        except AddressValueError:
            self.logger.warning(f"Invalid source IP for asset matching: {source_ip}")
            return None

    def get_matching_assets_summary(self, source_ips: List[str]) -> Dict[str, Any]:
        """
        Get a summary of asset matches for a list of source IPs.

        Args:
            source_ips: List of IP addresses to match

        Returns:
            Summary dictionary with match statistics and details
        """
        matches = []
        unmatched = []

        for ip in source_ips:
            asset = self.find_matching_asset(ip)
            if asset:
                matches.append({
                    "source_ip": ip,
                    "asset_name": asset.get("name", ""),
                    "asset_id": asset.get("id", ""),
                    "asset_type": asset.get("type", "vm"),  # Default to vm if not specified
                    "account_name": asset.get("account_name", ""),
                    "vpc_id": asset.get("vpc_id", ""),
                    "ips_or_cidrs": asset.get("ips_or_cidrs", []),
                })
            else:
                unmatched.append(ip)

        return {
            "total_ips": len(source_ips),
            "matched_count": len(matches),
            "unmatched_count": len(unmatched),
            "matches": matches,
            "unmatched_ips": unmatched,
        }


class CoPilotAssetLoader:
    """Loads and processes CoPilot app domains data."""

    def __init__(self, input_dir: Path):
        """
        Initialize CoPilotAssetLoader.

        Args:
            input_dir: Directory containing input files
        """
        self.input_dir = input_dir
        self.logger = logging.getLogger(__name__)

    def load_copilot_assets(self, filename: str = "copilot_app_domains.json") -> Optional[List[Dict[str, Any]]]:
        """
        Load CoPilot app domains data from JSON file.

        Args:
            filename: Name of the CoPilot app domains file

        Returns:
            List of asset dictionaries or None if file not found/invalid
        """
        file_path = self.input_dir / filename

        if not file_path.exists():
            self.logger.info(f"CoPilot app domains file not found: {file_path}")
            return None

        try:
            with open(file_path, encoding='utf-8') as f:
                data = json.load(f)

            # Extract resources array if present
            if isinstance(data, dict) and "resources" in data:
                assets = data["resources"]
            elif isinstance(data, list):
                assets = data
            else:
                self.logger.error(f"Invalid CoPilot app domains file format: {file_path}")
                return None

            self.logger.info(f"Loaded {len(assets)} assets from CoPilot app domains file")
            return list(assets)  # Ensure we return a List[Dict[str, Any]]

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse CoPilot app domains JSON: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to load CoPilot app domains file: {e}")
            return None

    def validate_assets(self, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate and filter asset data for use with FQDN source IP matching.

        Args:
            assets: List of raw asset dictionaries

        Returns:
            List of validated asset dictionaries
        """
        valid_assets = []

        for asset in assets:
            # Check required fields
            if not asset.get("ips_or_cidrs"):
                continue

            # Ensure required metadata exists
            asset_name = asset.get("name", "")
            account_name = asset.get("account_name", "")

            if not asset_name and not account_name:
                self.logger.warning(f"Asset missing name and account_name: {asset.get('id', 'Unknown')}")
                continue

            valid_assets.append(asset)

        self.logger.info(f"Validated {len(valid_assets)} assets out of {len(assets)} total")
        return valid_assets

    def create_asset_matcher(self, filename: str = "copilot_app_domains.json") -> Optional[AssetMatcher]:
        """
        Create an AssetMatcher instance from CoPilot data.

        Args:
            filename: Name of the CoPilot app domains file

        Returns:
            AssetMatcher instance or None if data not available
        """
        assets = self.load_copilot_assets(filename)
        if not assets:
            return None

        validated_assets = self.validate_assets(assets)
        if not validated_assets:
            self.logger.warning("No valid assets found in CoPilot app domains file")
            return None

        return AssetMatcher(validated_assets)

    def get_assets_dataframe(self, filename: str = "copilot_app_domains.json") -> Optional[pd.DataFrame]:
        """
        Load CoPilot assets as a pandas DataFrame for analysis.

        Args:
            filename: Name of the CoPilot app domains file

        Returns:
            DataFrame with asset data or None if not available
        """
        assets = self.load_copilot_assets(filename)
        if not assets:
            return None

        # Flatten the asset data for DataFrame creation
        flattened_assets = []
        for asset in assets:
            base_data = {
                "name": asset.get("name", ""),
                "id": asset.get("id", ""),
                "account_name": asset.get("account_name", ""),
                "account_id": asset.get("account_id", ""),
                "type": asset.get("type", ""),
                "region": asset.get("region", ""),
                "vpc_id": asset.get("vpc_id", ""),
            }

            # Add each IP/CIDR as a separate row
            ips_or_cidrs = asset.get("ips_or_cidrs", [])
            if ips_or_cidrs:
                for ip_or_cidr in ips_or_cidrs:
                    row = base_data.copy()
                    row["ip_or_cidr"] = ip_or_cidr
                    flattened_assets.append(row)
            else:
                flattened_assets.append(base_data)

        return pd.DataFrame(flattened_assets)
