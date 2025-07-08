#!/usr/bin/env python3
"""
Main entry point for the legacy-to-DCF policy translator.

This script orchestrates the conversion of legacy Aviatrix firewall policies
to Distributed Cloud Firewall (DCF) format using a modular architecture.
"""

import argparse
import logging
import sys
from pathlib import Path

# Add the src directory to the Python path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import TranslationConfig


def get_arguments() -> argparse.Namespace:
    """Parse and return command line arguments."""
    parser = argparse.ArgumentParser(
        description="Legacy Aviatrix Firewall to DCF Policy Translator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input-dir ./input --output-dir ./output
  %(prog)s --debug --customer-name "Example Corp"
  %(prog)s --validate-only --loglevel INFO
        """,
    )

    # Input/Output paths
    parser.add_argument(
        "--input-dir",
        type=str,
        help="Path to directory containing legacy configuration files (default: ./input)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        help="Path to directory for generated DCF files (default: ./output)",
    )
    parser.add_argument(
        "--debug-dir", type=str, help="Path to directory for debug files (default: ./debug)"
    )

    # Processing options
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode with detailed output and debug files",
    )
    parser.add_argument(
        "--force", action="store_true", help="Force overwrite existing output files"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate input files without generating output",
    )

    # Logging
    parser.add_argument(
        "--loglevel",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: WARNING)",
    )

    # DCF configuration
    parser.add_argument(
        "--internet-sg-id",
        default="def000ad-0000-0000-0000-000000000001",
        help="Internet security group ID for DCF policies",
    )
    parser.add_argument(
        "--anywhere-sg-id",
        default="def000ad-0000-0000-0000-000000000000",
        help="Anywhere security group ID for DCF policies",
    )
    parser.add_argument(
        "--any-webgroup-id",
        default="def000ad-0000-0000-0000-000000000002",
        help="Any webgroup ID for DCF policies",
    )
    parser.add_argument(
        "--default-web-port-ranges",
        nargs="+",
        default=["80", "443"],
        help="Default web port ranges for webgroup policies (space separated)",
    )
    parser.add_argument(
        "--global-catch-all-action",
        default="PERMIT",
        choices=["PERMIT", "DENY"],
        help="Global catch-all policy action (default: PERMIT)",
    )

    # Customer context
    parser.add_argument("--customer-name", type=str, help="Customer name for naming context")

    return parser.parse_args()


def setup_logging(config: TranslationConfig) -> None:
    """Configure logging based on configuration."""
    log_level = (
        getattr(logging, config.loglevel) if hasattr(config, "loglevel") else logging.WARNING
    )

    # Configure logging format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    if config.enable_debug:
        log_format = (
            "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        )

    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(config.output_dir / "translation.log")
            if config.output_dir
            else logging.StreamHandler(),
        ],
    )


def validate_environment(config: TranslationConfig) -> bool:
    """Validate the environment and configuration."""
    logging.info("Validating environment and configuration...")

    # Validate configuration
    config_errors = config.validate()
    if config_errors:
        logging.error("Configuration validation failed:")
        for error in config_errors:
            logging.error(f"  - {error}")
        return False

    # Ensure directories exist
    try:
        config.ensure_directories_exist()
    except Exception as e:
        logging.error(f"Failed to create directories: {e}")
        return False

    logging.info("Environment validation successful")
    return True


def main() -> int:
    """Main orchestration function."""
    # Parse arguments and create configuration
    args = get_arguments()
    config = TranslationConfig.from_args(args)

    # Add additional args to config
    if hasattr(args, "loglevel"):
        config.loglevel = args.loglevel
    if hasattr(args, "internet_sg_id"):
        config.internet_sg_id = args.internet_sg_id
    if hasattr(args, "anywhere_sg_id"):
        config.anywhere_sg_id = args.anywhere_sg_id
    if hasattr(args, "any_webgroup_id"):
        config.any_webgroup_id = args.any_webgroup_id
    if hasattr(args, "default_web_port_ranges"):
        config.default_web_port_ranges = args.default_web_port_ranges
    if hasattr(args, "global_catch_all_action"):
        config.global_catch_all_action = args.global_catch_all_action

    # Setup logging
    setup_logging(config)

    logging.info("Starting Legacy-to-DCF Policy Translation")
    logging.info(f"Input directory: {config.input_dir}")
    logging.info(f"Output directory: {config.output_dir}")
    logging.info(f"Debug mode: {config.enable_debug}")

    # Validate environment
    if not validate_environment(config):
        logging.error("Environment validation failed")
        return 1

    # If validate-only mode, stop here
    if config.validate_only:
        logging.info("Validation-only mode: Environment checks passed")
        return 0

    try:
        # Import modular components

        import pandas as pd
        from analysis.fqdn_analysis import FQDNAnalyzer
        from analysis.policy_validators import PolicyValidator
        from analysis.translation_reporter import TranslationReporter
        from data.exporters import DataExporter
        from data.loaders import ConfigurationLoader
        from data.processors import DataProcessor
        from translation.fqdn_handlers import FQDNHandler
        from translation.policies import (
            L4PolicyHandler,
            build_catch_all_policies,
            build_internet_policies,
        )
        from translation.smartgroups import SmartGroupManager
        from utils.data_processing import (
            deduplicate_policy_names,
            pretty_parse_vpc_name,
            translate_port_to_port_range,
        )

        logging.info("Loading legacy configuration files...")

        # Initialize data loader and load all configuration
        loader = ConfigurationLoader(config)
        config_data = loader.load_all_configuration()

        # Extract DataFrames from loaded data
        fw_tag_df = config_data.get("firewall_tag", pd.DataFrame())
        fw_policy_df = config_data.get("firewall_policy", pd.DataFrame())
        fw_gw_df = config_data.get("firewall", pd.DataFrame())
        fqdn_tag_rule_df = config_data.get("fqdn_tag_rule", pd.DataFrame())
        fqdn_df = config_data.get("fqdn", pd.DataFrame())
        gateways_df = config_data.get("gateways", pd.DataFrame())

        # Initialize data processor and process policies
        processor = DataProcessor(config)

        # Process L4 policies if available
        if len(fw_policy_df) > 0:
            logging.info("Processing L4 firewall policies...")

            # Validate and clean policies
            fw_policy_df, fw_tag_df, stateless_alerts = processor.process_firewall_policies(
                fw_policy_df, fw_tag_df
            )

            # Update dataframes with processed data (already done by unpacking above)
            # fw_policy_df = validation_result.cleaned_policies
            # fw_tag_df = validation_result.cleaned_tags

            if config.enable_debug:
                fw_policy_df.to_csv(config.debug_dir / "clean_policies.csv")
        else:
            validation_result = None

        # Initialize SmartGroup manager and create SmartGroups
        logging.info("Building SmartGroups...")

        # Initialize CoPilot asset matcher if available
        asset_matcher = None
        copilot_assets_df = config_data.get("copilot_assets")
        if copilot_assets_df is not None and not copilot_assets_df.empty:
            from data.copilot_loader import CoPilotAssetLoader
            copilot_loader = CoPilotAssetLoader(config.input_dir)
            asset_matcher = copilot_loader.create_asset_matcher()
            if asset_matcher:
                logging.info("CoPilot asset matcher initialized for advanced FQDN source IP translation")

        sg_manager = SmartGroupManager(config, asset_matcher)
        smartgroup_results = sg_manager.create_all_smartgroups(
            fw_policy_df, fw_tag_df, gateways_df, fqdn_df=fqdn_df
        )
        smartgroups_df = smartgroup_results.get("complete_smartgroups", pd.DataFrame())

        # Annotate fqdn_df with source IP filter information
        source_ip_smartgroups_df = smartgroup_results.get("source_ip_smartgroups", pd.DataFrame())

        # Trust the data loader's determination of has_source_ip_filter
        # which is based on actual source_ip_list presence in FQDN config
        logging.info(f"FQDN tags with source IP filters: {fqdn_df['has_source_ip_filter'].sum()}")

        # Debug log the mappings
        if config.enable_debug:
            logging.debug(f"Source IP SmartGroups created: {len(source_ip_smartgroups_df)}")
            if not source_ip_smartgroups_df.empty:
                logging.debug(f"Source IP SmartGroup names: {list(source_ip_smartgroups_df['name'])}")
            fqdn_tags_with_filters = fqdn_df[fqdn_df['has_source_ip_filter']]['fqdn_tag'].tolist()
            logging.debug(f"FQDN tags with actual source IP filters: {fqdn_tags_with_filters}")

        # Initialize L4 policy handler and create L4 policies
        l4_dcf_policies_df = pd.DataFrame()
        if len(fw_policy_df) > 0:
            logging.info("Building L4 DCF policies...")
            l4_handler = L4PolicyHandler(config)
            l4_dcf_policies_df = l4_handler.build_l4_policies(fw_policy_df)
            l4_dcf_policies_df["web_groups"] = None

        # Initialize unsupported FQDN tracker for comprehensive reporting
        from translation.unsupported_fqdn_tracker import UnsupportedFQDNTracker
        unsupported_fqdn_tracker = UnsupportedFQDNTracker()

        # Initialize FQDN handler and process FQDN rules
        logging.info("Processing FQDN rules...")
        fqdn_handler = FQDNHandler(
            config.default_web_port_ranges,
            translate_port_to_port_range,
            pretty_parse_vpc_name,
            deduplicate_policy_names,
            unsupported_fqdn_tracker
        )

        # Process FQDN rules
        webgroup_rules_df, hostname_rules_df, unsupported_rules_df = (
            fqdn_handler.process_fqdn_rules(fqdn_tag_rule_df, fqdn_df)
        )

        # Create hostname SmartGroups
        hostname_smartgroups_df = fqdn_handler.build_hostname_smartgroups(hostname_rules_df)

        # Create WebGroups
        if config.enable_debug:
            webgroup_rules_df.to_csv(config.debug_dir / "clean_fqdn_webgroups.csv")
            hostname_rules_df.to_csv(config.debug_dir / "clean_fqdn_hostnames.csv")

        webgroups_df = fqdn_handler.build_webgroups(webgroup_rules_df)

        # Export SmartGroups and WebGroups to CSV (SmartGroups now include all types)
        smartgroups_df.to_csv(config.get_output_file_path("smart_groups_csv"))

        # Create policies
        logging.info("Building internet and hostname policies...")
        internet_rules_df = build_internet_policies(
            gateways_df,
            fqdn_df,
            webgroups_df,
            config.any_webgroup_id,
            config.internet_sg_id,
            config.anywhere_sg_id,
            config.default_web_port_ranges,
            hostname_smartgroups_df,
            hostname_rules_df,
        )

        logging.info("Building catch-all policies...")
        catch_all_rules_df = build_catch_all_policies(
            gateways_df,
            fw_gw_df,
            config.internet_sg_id,
            config.anywhere_sg_id,
            config.global_catch_all_action,
        )

        # Merge all policies
        logging.info("Merging all policies...")
        policy_dataframes = []
        if len(fw_policy_df) > 0 and len(l4_dcf_policies_df) > 0:
            policy_dataframes.append(l4_dcf_policies_df)
        if len(internet_rules_df) > 0:
            policy_dataframes.append(internet_rules_df)
        if len(catch_all_rules_df) > 0:
            policy_dataframes.append(catch_all_rules_df)

        # Create final policy list
        if policy_dataframes:
            full_policy_list = pd.concat(policy_dataframes, ignore_index=True)
            full_policy_list = deduplicate_policy_names(full_policy_list)
        else:
            full_policy_list = pd.DataFrame()

        # Combine SmartGroups and hostname SmartGroups for export
        combined_smartgroups_df = smartgroups_df.copy()
        if len(hostname_smartgroups_df) > 0:
            # Ensure hostname SmartGroups only include columns compatible with regular SmartGroups
            hostname_sg_for_export = hostname_smartgroups_df[["name", "selector"]].copy()
            combined_smartgroups_df = pd.concat([combined_smartgroups_df, hostname_sg_for_export], ignore_index=True)
            logging.info(f"Combined {len(smartgroups_df)} regular SmartGroups with {len(hostname_smartgroups_df)} hostname SmartGroups for export")

        # Prepare output data (including input data for reporting)
        output_data = {
            # Input data for summary reporting
            "fw_policy_df": fw_policy_df,
            "fw_tag_df": fw_tag_df,
            "fqdn_df": fqdn_df,
            "fqdn_tag_rule_df": fqdn_tag_rule_df,
            "gateways_df": gateways_df,
            # Output data
            "smartgroups_df": combined_smartgroups_df,
            "webgroups_df": webgroups_df,
            "hostname_smartgroups_df": hostname_smartgroups_df,
            "l4_dcf_policies_df": l4_dcf_policies_df,
            "internet_rules_df": internet_rules_df,
            "catch_all_rules_df": catch_all_rules_df,
            "full_policy_list": full_policy_list,
            "unsupported_rules_df": unsupported_rules_df,
            "unsupported_fqdn_domains_df": unsupported_fqdn_tracker.to_dataframe(),
        }

        # Initialize data exporter and export all outputs
        logging.info("Exporting translation results...")
        exporter = DataExporter(config)
        # Remove unused variable assignment
        # exported_files = exporter.export_all_outputs(output_data)
        exporter.export_all_outputs(output_data)

        # Run analysis if enabled
        if config.enable_debug:
            logging.info("Running FQDN analysis...")
            fqdn_analyzer = FQDNAnalyzer()
            fqdn_analysis = fqdn_analyzer.analyze_fqdn_rules(fqdn_tag_rule_df, fqdn_df)

            # Run policy validation
            logging.info("Running policy validation...")
            validator = PolicyValidator()

            # Create a comprehensive validation result
            validation_result = validator.perform_comprehensive_validation(fw_policy_df, fw_tag_df)

            # Generate comprehensive report
            logging.info("Generating analysis report...")
            reporter = TranslationReporter(config.output_dir)
            report = reporter.generate_comprehensive_report(
                output_data, fqdn_analysis, validation_result
            )

            # Export reports
            reporter.export_report_to_json(report)
            reporter.export_summary_to_text(report)

        # Show final counts
        hostname_sg_count = len(hostname_smartgroups_df) if len(hostname_smartgroups_df) > 0 else 0
        # hostname_policy_count now included in internet_rules_df, not separate

        logging.info("Translation completed successfully!")
        smartgroups_total = len(smartgroups_df)
        logging.info(
            f"SmartGroups created: {smartgroups_total} "
            f"(including {hostname_sg_count} hostname SmartGroups)"
        )
        logging.info(f"WebGroups created: {len(webgroups_df)}")
        # hostname_policy_count now included in internet_rules_df, not separate
        logging.info(f"Total DCF Policies created: {len(full_policy_list)}")
        
        # Log unsupported FQDN summary
        unsupported_fqdn_tracker.log_summary()

        return 0

    except Exception as e:
        logging.error(f"Translation failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
