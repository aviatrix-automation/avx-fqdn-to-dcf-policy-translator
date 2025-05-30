"""
Data export module for the legacy-to-DCF policy translator.

Handles exporting processed data to various formats including Terraform JSON.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict

import pandas as pd

sys.path.append(str(Path(__file__).parent.parent))
from config import TranslationConfig


class TerraformExporter:
    """Exports DataFrames to Terraform JSON format."""

    def __init__(self, config: TranslationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def export_dataframe_to_tf(
        self, df: pd.DataFrame, resource_name: str, name_column: str
    ) -> Path:
        """
        Export a DataFrame to Terraform JSON format.

        Args:
            df: DataFrame to export
            resource_name: Terraform resource name (e.g., 'aviatrix_smart_group')
            name_column: Column to use as the resource key

        Returns:
            Path to the exported file
        """
        if df.empty:
            self.logger.warning(f"Attempting to export empty DataFrame for {resource_name}")
            # Create empty structure
            tf_resource_dict: Dict[str, Any] = {"resource": {resource_name: {}}}
        else:
            # Convert DataFrame to Terraform format
            records = df.to_dict(orient="records")
            tf_resource_dict = {record[name_column]: record for record in records}
            tf_resource_dict = {"resource": {resource_name: tf_resource_dict}}

        # Determine output file path
        output_file = Path(self.config.output_dir) / f"{resource_name}.tf.json"

        try:
            with open(output_file, "w") as json_file:
                json.dump(tf_resource_dict, json_file, indent=2)

            self.logger.info(f"Exported {len(df)} {resource_name} resources to {output_file}")
            return output_file

        except Exception as e:
            self.logger.error(f"Failed to export {resource_name} to {output_file}: {e}")
            raise

    def export_policies_to_tf(self, policies_df: pd.DataFrame) -> Path:
        """
        Export DCF policies to Terraform JSON format.

        Args:
            policies_df: DataFrame containing DCF policies

        Returns:
            Path to the exported file
        """
        if policies_df.empty:
            self.logger.warning("Attempting to export empty policies DataFrame")
            policy_dict: Dict[str, Any] = {
                "resource": {
                    "aviatrix_distributed_firewalling_policy_list": {
                        "distributed_firewalling_policy_list_1": {"policies": []}
                    }
                }
            }
        else:
            # Add required fields for DCF
            policies_copy = policies_df.copy()
            policies_copy["exclude_sg_orchestration"] = True

            policy_records = policies_copy.to_dict(orient="records")
            policy_dict = {
                "resource": {
                    "aviatrix_distributed_firewalling_policy_list": {
                        "distributed_firewalling_policy_list_1": {"policies": policy_records}
                    }
                }
            }

        output_file = Path(self.config.get_output_file_path("dcf_policies"))

        try:
            with open(output_file, "w") as json_file:
                json.dump(policy_dict, json_file, indent=2)

            self.logger.info(f"Exported {len(policies_df)} DCF policies to {output_file}")
            return output_file

        except Exception as e:
            self.logger.error(f"Failed to export DCF policies to {output_file}: {e}")
            raise

    def create_main_tf(self) -> Path:
        """
        Create the main.tf file with provider configuration.

        Returns:
            Path to the created main.tf file
        """
        main_tf_content = """terraform {
  required_providers {
    aviatrix = {
      source  = "AviatrixSystems/aviatrix"
      version = ">=8.0"
    }
  }
}

provider "aviatrix" {
  skip_version_validation = true
}"""

        output_file = Path(self.config.get_output_file_path("main_tf"))

        try:
            with open(output_file, "w") as f:
                f.write(main_tf_content)

            self.logger.info(f"Created main.tf file: {output_file}")
            return output_file

        except Exception as e:
            self.logger.error(f"Failed to create main.tf file: {e}")
            raise


class CSVExporter:
    """Exports DataFrames to CSV format for analysis and debugging."""

    def __init__(self, config: TranslationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def export_to_csv(self, df: pd.DataFrame, filename: str, directory: str = "output") -> Path:
        """
        Export DataFrame to CSV file.

        Args:
            df: DataFrame to export
            filename: Name of the CSV file (with or without .csv extension)
            directory: Directory type ("output" or "debug")

        Returns:
            Path to the exported file
        """
        if not filename.endswith(".csv"):
            filename += ".csv"

        if directory == "debug":
            output_file = Path(self.config.debug_dir) / filename
        else:
            output_file = Path(self.config.output_dir) / filename

        try:
            df.to_csv(output_file, index=False)
            self.logger.info(f"Exported {len(df)} records to {output_file}")
            return output_file

        except Exception as e:
            self.logger.error(f"Failed to export CSV to {output_file}: {e}")
            raise

    def export_analysis_files(self, data: Dict[str, pd.DataFrame]) -> Dict[str, Path]:
        """
        Export various analysis and debug CSV files.

        Args:
            data: Dictionary of DataFrames to export

        Returns:
            Dictionary mapping file types to their paths
        """
        exported_files = {}

        # Export main analysis files to output directory
        output_exports = {
            "full_policy_list": "full_policy_list.csv",
            "smartgroups": "smartgroups.csv",
            "removed_duplicates": "removed_duplicate_policies.csv",
        }

        for key, filename in output_exports.items():
            if key in data and not data[key].empty:
                exported_files[key] = self.export_to_csv(data[key], filename, "output")

        # Export debug files if debug mode is enabled
        if self.config.enable_debug:
            debug_exports = {
                "clean_policies": "clean_policies.csv",
                "clean_fqdn": "clean_fqdn.csv",
                "clean_fqdn_hostnames": "clean_fqdn_hostnames.csv",
                "clean_fqdn_webgroups": "clean_fqdn_webgroups.csv",
                "unsupported_fqdn_rules": "unsupported_fqdn_rules.csv",
            }

            for key, filename in debug_exports.items():
                if key in data and not data[key].empty:
                    exported_files[key] = self.export_to_csv(data[key], filename, "debug")

        return exported_files


class ReportExporter:
    """Generates and exports summary reports."""

    def __init__(self, config: TranslationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def generate_translation_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of the translation results.

        Args:
            data: Dictionary containing translation results

        Returns:
            Dictionary containing summary statistics
        """
        summary: Dict[str, Any] = {
            "input_summary": {},
            "output_summary": {},
            "translation_stats": {}
        }

        # Input summary
        input_counts = {}
        for key in ["fw_policy_df", "fw_tag_df", "fqdn_df", "fqdn_tag_rule_df", "gateways_df"]:
            if key in data:
                input_counts[key.replace("_df", "")] = len(data[key])
        summary["input_summary"] = input_counts

        # Output summary
        output_counts = {}
        for key in ["smartgroups_df", "webgroups_df", "hostname_policies_df", "full_policy_list"]:
            if key in data:
                output_counts[key.replace("_df", "")] = len(data[key])
        summary["output_summary"] = output_counts

        # Translation statistics
        stats = {}
        if "hostname_smartgroups_df" in data:
            stats["hostname_smartgroups"] = len(data["hostname_smartgroups_df"])
        if "unsupported_rules_df" in data:
            stats["unsupported_rules"] = len(data["unsupported_rules_df"])
        summary["translation_stats"] = stats

        return summary

    def export_summary_report(self, summary: Dict[str, Any]) -> Path:
        """
        Export translation summary to JSON file.

        Args:
            summary: Summary dictionary

        Returns:
            Path to the exported summary file
        """
        output_file = Path(self.config.output_dir) / "translation_summary.json"

        try:
            with open(output_file, "w") as f:
                json.dump(summary, f, indent=2)

            self.logger.info(f"Exported translation summary to {output_file}")
            return output_file

        except Exception as e:
            self.logger.error(f"Failed to export summary report: {e}")
            raise


class DataExporter:
    """Main data exporter that orchestrates all export operations."""

    def __init__(self, config: TranslationConfig):
        self.config = config
        self.tf_exporter = TerraformExporter(config)
        self.csv_exporter = CSVExporter(config)
        self.report_exporter = ReportExporter(config)
        self.logger = logging.getLogger(__name__)

    def export_all_outputs(self, data: Dict[str, Any]) -> Dict[str, Path]:
        """
        Export all translation outputs.

        Args:
            data: Dictionary containing all translation data

        Returns:
            Dictionary mapping output types to their file paths
        """
        exported_files = {}

        try:
            # Export Terraform files
            if "smartgroups_df" in data and not data["smartgroups_df"].empty:
                exported_files["smartgroups_tf"] = self.tf_exporter.export_dataframe_to_tf(
                    data["smartgroups_df"], "aviatrix_smart_group", "name"
                )

            if "webgroups_df" in data and not data["webgroups_df"].empty:
                exported_files["webgroups_tf"] = self.tf_exporter.export_dataframe_to_tf(
                    data["webgroups_df"][["name", "selector"]], "aviatrix_web_group", "name"
                )

            if "full_policy_list" in data:
                exported_files["policies_tf"] = self.tf_exporter.export_policies_to_tf(
                    data["full_policy_list"]
                )

            # Create main.tf
            exported_files["main_tf"] = self.tf_exporter.create_main_tf()

            # Export CSV files
            csv_files = self.csv_exporter.export_analysis_files(data)
            exported_files.update(csv_files)

            # Generate and export summary report
            summary = self.report_exporter.generate_translation_summary(data)
            exported_files["summary_report"] = self.report_exporter.export_summary_report(summary)

            self.logger.info(f"Successfully exported {len(exported_files)} output files")
            return exported_files

        except Exception as e:
            self.logger.error(f"Failed to export outputs: {e}")
            raise
