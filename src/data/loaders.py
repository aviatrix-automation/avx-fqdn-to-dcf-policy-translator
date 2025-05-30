"""
Data loading module for the legacy-to-DCF policy translator.

Handles loading and parsing of Terraform configuration files and JSON data.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict

import pandas as pd

try:
    import python_hcl2 as hcl
except ImportError:
    import hcl2 as hcl

import sys

sys.path.append(str(Path(__file__).parent.parent))

from config import TranslationConfig
from utils.data_processing import sanitize_terraform_file


class TerraformLoader:
    """Loads Terraform configuration files and converts them to DataFrames."""

    def __init__(self, config: TranslationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def load_tf_resource(self, resource_name: str) -> pd.DataFrame:
        """
        Load a Terraform resource file and convert to DataFrame.

        Args:
            resource_name: Name of the resource (e.g., 'firewall', 'firewall_policy')

        Returns:
            DataFrame containing the resource data
        """
        file_path = self.config.get_input_file_path(resource_name)

        if not file_path.exists():
            self.logger.warning(f"Terraform file not found: {file_path}")
            return pd.DataFrame()

        try:
            # Sanitize the Terraform file to remove $$hashKey artifacts
            sanitized_file_path = sanitize_terraform_file(str(file_path))

            try:
                with open(sanitized_file_path) as fp:
                    resource_dict = hcl.load(fp)
            finally:
                # Clean up the temporary sanitized file
                import os

                try:
                    os.unlink(sanitized_file_path)
                except OSError:
                    # Ignore cleanup errors like file not found or permission denied
                    pass

            if "resource" in resource_dict.keys():
                resource_data = resource_dict["resource"]

                # Handle different formats returned by hcl vs hcl2
                if isinstance(resource_data, list):
                    # hcl2 returns a list of resource dictionaries
                    target_resources = {}
                    for resource_item in resource_data:
                        if isinstance(resource_item, dict):
                            resource_instances = resource_item.get(f"aviatrix_{resource_name}", {})
                            if resource_instances:
                                target_resources.update(resource_instances)
                    resource_dict = target_resources
                elif isinstance(resource_data, dict):
                    # hcl returns a nested dictionary
                    resource_dict = resource_data.get(f"aviatrix_{resource_name}", {})
                else:
                    resource_dict = {}
            else:
                resource_dict = {}

            resource_df = self._create_dataframe(resource_dict, resource_name)

            self.logger.info(f"Loaded {len(resource_df)} {resource_name} resources")
            self.logger.debug(f"Sample {resource_name} data:\n{resource_df.head()}")

            return resource_df

        except Exception as e:
            self.logger.error(f"Failed to load {resource_name} from {file_path}: {e}")
            return pd.DataFrame()

    def _create_dataframe(self, tf_resource: Dict[str, Any], resource_name: str) -> pd.DataFrame:
        """
        Convert Terraform resource dictionary to DataFrame.

        Args:
            tf_resource: Dictionary of Terraform resources
            resource_name: Name of the resource for debug output

        Returns:
            DataFrame containing the resource data
        """
        if not tf_resource:
            return pd.DataFrame()

        try:
            df = pd.DataFrame([tf_resource[x] for x in tf_resource.keys()])

            # Save debug file if enabled
            if self.config.enable_debug:
                debug_file = self.config.debug_dir / f"{resource_name}.csv"
                df.to_csv(debug_file, index=False)
                self.logger.debug(f"Saved debug file: {debug_file}")

            return df

        except Exception as e:
            self.logger.error(f"Failed to create DataFrame for {resource_name}: {e}")
            return pd.DataFrame()

    def load_all_terraform_resources(self) -> Dict[str, pd.DataFrame]:
        """
        Load all Terraform resource files.

        Returns:
            Dictionary mapping resource names to DataFrames
        """
        resources = {}

        # Standard Terraform resource files
        resource_names = [
            "firewall_tag",
            "firewall_policy",
            "firewall",
            "fqdn_tag_rule",
            "fqdn",
            "smart_group",
        ]

        for resource_name in resource_names:
            resources[resource_name] = self.load_tf_resource(resource_name)

        return resources


class GatewayDetailsLoader:
    """Loads gateway details from JSON configuration."""

    def __init__(self, config: TranslationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def load_gateway_details(self) -> pd.DataFrame:
        """
        Load gateway details from JSON file.

        Returns:
            DataFrame containing gateway configuration data
        """
        file_path = self.config.get_input_file_path("gateway_details")

        if not file_path.exists():
            self.logger.error(f"Gateway details file not found: {file_path}")
            return pd.DataFrame()

        try:
            with open(file_path) as fp:
                gateway_details = json.load(fp)

            if "results" not in gateway_details:
                self.logger.error("Invalid gateway details format - missing 'results' key")
                return pd.DataFrame()

            gateways_df = pd.DataFrame(gateway_details["results"])

            # Save debug file if enabled
            if self.config.enable_debug:
                debug_file = self.config.debug_dir / "gateway_details.csv"
                gateways_df.to_csv(debug_file, index=False)
                self.logger.debug(f"Saved gateway debug file: {debug_file}")

            self.logger.info(f"Loaded {len(gateways_df)} gateway configurations")
            return gateways_df

        except Exception as e:
            self.logger.error(f"Failed to load gateway details from {file_path}: {e}")
            return pd.DataFrame()


class ConfigurationLoader:
    """Main configuration loader that orchestrates all data loading."""

    def __init__(self, config: TranslationConfig):
        self.config = config
        self.tf_loader = TerraformLoader(config)
        self.gateway_loader = GatewayDetailsLoader(config)
        self.logger = logging.getLogger(__name__)

    def load_all_configuration(self) -> Dict[str, pd.DataFrame]:
        """
        Load all configuration data.

        Returns:
            Dictionary containing all loaded DataFrames
        """
        self.logger.info("Loading all configuration data...")

        # Load Terraform resources
        config_data = self.tf_loader.load_all_terraform_resources()

        # Load gateway details
        config_data["gateways"] = self.gateway_loader.load_gateway_details()

        # Validate critical data is present
        self._validate_loaded_data(config_data)

        return config_data

    def _validate_loaded_data(self, config_data: Dict[str, pd.DataFrame]) -> None:
        """
        Validate that critical configuration data was loaded successfully.

        Args:
            config_data: Dictionary of loaded DataFrames
        """
        critical_resources = ["gateways"]
        warnings = []
        errors = []

        for resource in critical_resources:
            if resource not in config_data or config_data[resource].empty:
                errors.append(f"Critical resource '{resource}' is missing or empty")

        # Check for optional but commonly needed resources
        optional_resources = ["firewall_policy", "fqdn", "fqdn_tag_rule"]
        for resource in optional_resources:
            if resource not in config_data or config_data[resource].empty:
                warnings.append(f"Optional resource '{resource}' is missing or empty")

        # Log warnings
        for warning in warnings:
            self.logger.warning(warning)

        # Raise errors for critical missing data
        if errors:
            error_msg = "Critical configuration validation failed:\n" + "\n".join(errors)
            self.logger.error(error_msg)
            raise ValueError(error_msg)
