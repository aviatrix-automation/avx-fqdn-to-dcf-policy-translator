"""
FQDN Processing Module for Legacy to DCF Policy Translation

This module handles all FQDN (Fully Qualified Domain Name) related processing including:
- Domain validation and filtering for DCF 8.0 compatibility
- FQDN rule categorization (webgroup vs hostname smartgroup)
- Webgroup creation for HTTP/HTTPS traffic
- Hostname SmartGroup creation for non-HTTP traffic
- FQDN policy generation

Key Components:
- Domain validation using DCF 8.0 SNI regex patterns
- Webgroup creation for standard web ports (80/443)
- Hostname SmartGroup creation for non-standard ports and protocols
- Policy generation for both webgroup and hostname-based rules
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from config import TranslationConfig
from data.processors import DataCleaner

# Configure pandas to avoid future warnings about downcasting
pd.set_option("future.no_silent_downcasting", True)

# DCF 8.0 SNI domain validation regex pattern
DCF_SNI_DOMAIN_PATTERN = re.compile(r"^(\*|\*\.[-A-Za-z0-9_.]+|[-A-Za-z0-9_.]+)$")


class FQDNValidator:
    """Validates domains for DCF 8.0 compatibility."""

    @staticmethod
    def validate_sni_domain_for_dcf(domain: str) -> bool:
        """
        Validate if a domain matches DCF 8.0 SNI filter requirements.

        Args:
            domain: The domain to validate

        Returns:
            True if domain is valid for DCF 8.0, False otherwise

        The DCF 8.0 regex pattern allows:
        - Exact wildcard: *
        - Wildcard with subdomain: *.domain.com
        - Regular domain: domain.com

        Invalid patterns like "*domain.com" (wildcard without dot) are rejected.
        """
        if not domain or not isinstance(domain, str):
            return False

        domain = domain.strip()
        return bool(DCF_SNI_DOMAIN_PATTERN.match(domain))

    @staticmethod
    def filter_domains_for_dcf_compatibility(
        fqdn_list: List[str], webgroup_name: Optional[str] = None
    ) -> Tuple[List[str], List[str]]:
        """
        Filter FQDN list to only include DCF 8.0 compatible domains.

        Args:
            fqdn_list: List of domain strings
            webgroup_name: Name of webgroup for logging context (optional)

        Returns:
            Tuple of (valid_domains, invalid_domains)
        """
        valid_domains = []
        invalid_domains = []

        webgroup_context = f" for webgroup '{webgroup_name}'" if webgroup_name else ""

        for domain in fqdn_list:
            if FQDNValidator.validate_sni_domain_for_dcf(domain):
                valid_domains.append(domain)
            else:
                invalid_domains.append(domain)

        if invalid_domains:
            logging.warning(
                f"Filtered {len(invalid_domains)} DCF 8.0 incompatible SNI domains"
                f"{webgroup_context}: {invalid_domains}"
            )

        if valid_domains:
            logging.info(
                f"Retained {len(valid_domains)} DCF 8.0 compatible domains{webgroup_context}"
            )

        return valid_domains, invalid_domains


class FQDNRuleProcessor:
    """Processes FQDN rules and categorizes them for different DCF components."""

    def __init__(self, default_web_port_ranges: List[str]):
        """
        Initialize with configuration.

        Args:
            default_web_port_ranges: List of port ranges considered web traffic
                (e.g., ['80', '443'])
        """
        self.default_web_port_ranges = set(default_web_port_ranges)

    def eval_unsupported_webgroups(
        self, fqdn_tag_rule_df: pd.DataFrame, fqdn_df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Split FQDN rules into webgroup-supported and hostname smartgroup rules.
        All FQDN rules are now supported - no more truly unsupported rules.

        Args:
            fqdn_tag_rule_df: DataFrame containing FQDN tag rules
            fqdn_df: DataFrame containing FQDN configurations

        Returns:
            Tuple of (webgroup_rules, hostname_rules, truly_unsupported_rules)
        """
        fqdn_tag_rule_df = fqdn_tag_rule_df.merge(
            fqdn_df, left_on="fqdn_tag_name", right_on="fqdn_tag", how="left"
        )

        # IMPORTANT: Only process enabled FQDN tags to maintain consistency
        # with existing webgroup logic
        enabled_fqdn_rules = fqdn_tag_rule_df[fqdn_tag_rule_df["fqdn_enabled"]]

        # Rules that can use webgroups (HTTP/HTTPS on standard web ports)
        webgroup_rules = enabled_fqdn_rules[
            (enabled_fqdn_rules["protocol"].str.lower().isin(["tcp", "http", "https"]))
            & (enabled_fqdn_rules["port"].isin(self.default_web_port_ranges))
        ]

        # ALL other enabled rules use hostname smartgroups
        # (including protocol='all', SSH, blank ports)
        hostname_rules = enabled_fqdn_rules[
            ~(
                (enabled_fqdn_rules["protocol"].str.lower().isin(["tcp", "http", "https"]))
                & (enabled_fqdn_rules["port"].isin(self.default_web_port_ranges))
            )
        ]

        # Convert protocol "all" to "ANY" for DCF compatibility
        hostname_rules = hostname_rules.copy()
        hostname_rules.loc[hostname_rules["protocol"] == "all", "protocol"] = "ANY"

        # Handle blank ports by setting to "ALL" for hostname SmartGroups
        hostname_rules.loc[hostname_rules["port"] == "", "port"] = "ALL"

        # No more truly unsupported rules - everything is handled
        unsupported_rules = pd.DataFrame()

        logging.info(
            f"FQDN rules split: {len(webgroup_rules)} webgroup rules, "
            f"{len(hostname_rules)} hostname rules, {len(unsupported_rules)} unsupported rules"
        )

        return webgroup_rules, hostname_rules, unsupported_rules


class WebGroupBuilder:
    """Builds DCF WebGroups from FQDN rules."""

    def __init__(self, unsupported_fqdn_tracker: Optional[Any] = None) -> None:
        self.cleaner = DataCleaner(TranslationConfig())
        self.all_invalid_domains: List[Dict[str, str]] = []
        self.unsupported_fqdn_tracker = unsupported_fqdn_tracker

    def build_webgroup_df(self, fqdn_tag_rule_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build WebGroups DataFrame from FQDN tag rules.

        Args:
            fqdn_tag_rule_df: DataFrame containing FQDN tag rules

        Returns:
            DataFrame containing WebGroup configurations
        """
        # Handle empty DataFrame case (e.g., when all FQDN tags are disabled)
        if len(fqdn_tag_rule_df) == 0:
            logging.info("No FQDN tag rules provided for WebGroup creation")
            return pd.DataFrame(columns=["name", "selector"])
        
        fqdn_tag_rule_df = (
            fqdn_tag_rule_df.groupby(["fqdn_tag_name", "protocol", "port", "fqdn_mode"])["fqdn"]
            .apply(list)
            .reset_index()
        )

        def create_webgroup_name(row: pd.Series) -> str:
            # Replace white/black mode with permit/deny in the webgroup name
            mode_suffix = "permit" if row["fqdn_mode"] == "white" else "deny"
            return "{}_{}_{}_{}".format(
                row["fqdn_tag_name"], mode_suffix, row["protocol"], row["port"]
            )

        fqdn_tag_rule_df["name"] = fqdn_tag_rule_df.apply(create_webgroup_name, axis=1)

        # Filter domains for DCF 8.0 compatibility before creating selectors
        def filter_and_create_selector(row: pd.Series) -> Dict[str, Any]:
            webgroup_name = row["name"]
            fqdn_tag_name = row["fqdn_tag_name"]
            protocol = row["protocol"].upper()
            port = str(row["port"])
            valid_domains, invalid_domains = FQDNValidator.filter_domains_for_dcf_compatibility(
                row["fqdn"], webgroup_name
            )

            if invalid_domains:
                # Store invalid domains for reporting using instance attribute (legacy format)
                self.all_invalid_domains.extend(
                    [{"webgroup": webgroup_name, "domain": domain} for domain in invalid_domains]
                )
                
                # Add detailed records to the tracker if available
                if self.unsupported_fqdn_tracker:
                    for domain in invalid_domains:
                        self.unsupported_fqdn_tracker.add_invalid_domain(
                            fqdn_tag_name=fqdn_tag_name,
                            webgroup_name=webgroup_name,
                            domain=domain,
                            port=port,
                            protocol=protocol,
                            reason="DCF 8.0 incompatible SNI domain pattern"
                        )

            return self._translate_fqdn_tag_to_sg_selector(valid_domains)

        fqdn_tag_rule_df["selector"] = fqdn_tag_rule_df.apply(filter_and_create_selector, axis=1)

        # Filter out WebGroups with empty match_expressions (all domains were filtered)
        initial_count = len(fqdn_tag_rule_df)
        # Check if match_expressions array is empty
        valid_mask = fqdn_tag_rule_df["selector"].apply(
            lambda x: len(x.get("match_expressions", [])) > 0
        )
        fqdn_tag_rule_df = fqdn_tag_rule_df[valid_mask]
        filtered_count = initial_count - len(fqdn_tag_rule_df)
        
        if filtered_count > 0:
            logging.warning(
                f"Filtered out {filtered_count} WebGroups with no valid DCF-compatible domains"
            )

        # Note: Using Aviatrix built-in "Any" webgroup instead of creating
        # custom any-domain webgroup
        fqdn_tag_rule_df = self.cleaner.remove_invalid_name_chars(fqdn_tag_rule_df, "name")

        # Log summary of filtered domains if any
        if self.all_invalid_domains:
            invalid_count = len(self.all_invalid_domains)
            logging.warning(f"Total DCF 8.0 incompatible SNI domains filtered: {invalid_count}")

            # Group by webgroup for detailed reporting
            from collections import defaultdict

            by_webgroup = defaultdict(list)
            for item in self.all_invalid_domains:
                by_webgroup[item["webgroup"]].append(item["domain"])

            for webgroup, domains in by_webgroup.items():
                logging.warning(
                    f"Webgroup '{webgroup}' had {len(domains)} filtered domains: {domains}"
                )

        return fqdn_tag_rule_df

    @staticmethod
    def _translate_fqdn_tag_to_sg_selector(fqdn_list: List[str]) -> Dict[str, Any]:
        """
        Translate FQDN list to SmartGroup selector format.

        Args:
            fqdn_list: List of FQDNs

        Returns:
            Dictionary containing match_expressions for SNI filtering
        """
        match_expressions = []
        for fqdn in fqdn_list:
            match_expressions.append({"snifilter": fqdn.strip()})
        return {"match_expressions": match_expressions}


class HostnameSmartGroupBuilder:
    """Builds hostname-based SmartGroups for non-webgroup FQDN rules."""

    def __init__(self) -> None:
        self.cleaner = DataCleaner(TranslationConfig())

    def build_hostname_smartgroups(self, hostname_rules_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build hostname SmartGroups for FQDN rules that don't use webgroups.
        Groups FQDNs by protocol/port combination for optimization.

        Args:
            hostname_rules_df: DataFrame containing hostname rules

        Returns:
            DataFrame containing hostname SmartGroups
        """
        if len(hostname_rules_df) == 0:
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

        logging.info(f"Created {len(hostname_sg_df)} hostname SmartGroups")
        return hostname_sg_df


class FQDNPolicyBuilder:
    """Builds DCF policies for FQDN-based rules."""

    def __init__(
        self,
        translate_port_to_port_range_func: Any,
        pretty_parse_vpc_name_func: Any,
        deduplicate_policy_names_func: Any,
    ) -> None:
        """
        Initialize with required utility functions.

        Args:
            translate_port_to_port_range_func: Function to convert ports to DCF port range format
            pretty_parse_vpc_name_func: Function to clean VPC names
            deduplicate_policy_names_func: Function to deduplicate policy names
        """
        self.translate_port_to_port_range = translate_port_to_port_range_func
        self.pretty_parse_vpc_name = pretty_parse_vpc_name_func
        self.deduplicate_policy_names = deduplicate_policy_names_func
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
        Creates one policy per unique (src VPC, protocol/port, hostname SmartGroup) combination.

        Args:
            gateways_df: DataFrame containing gateway information
            fqdn_df: DataFrame containing FQDN configurations
            hostname_smartgroups_df: DataFrame containing hostname SmartGroups
            hostname_rules_df: DataFrame containing hostname rules

        Returns:
            DataFrame containing hostname-based policies
        """
        if len(hostname_smartgroups_df) == 0 or len(hostname_rules_df) == 0:
            return pd.DataFrame()

        # Get egress VPCs (same logic as in build_internet_policies)
        egress_vpcs = gateways_df[
            (gateways_df["is_hagw"] == "no") & (gateways_df["egress_control"] == "Enabled")
        ].drop_duplicates(subset=["vpc_id", "vpc_region", "account_name"])

        if len(egress_vpcs) == 0:
            return pd.DataFrame()

        egress_vpcs = egress_vpcs[["fqdn_tags", "vpc_name", "vpc_id"]]
        egress_vpcs["src_smart_groups"] = egress_vpcs["vpc_id"]

        # Clean VPC names for SmartGroup references
        egress_vpcs["src_smart_groups"] = self.pretty_parse_vpc_name(
            egress_vpcs, "src_smart_groups"
        )
        egress_vpcs = self.cleaner.remove_invalid_name_chars(egress_vpcs, "src_smart_groups")

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
        # Handle NaN values in fqdn_enabled column before boolean filtering
        # Use explicit boolean conversion to avoid pandas downcasting warnings
        fqdn_enabled_col = egress_vpcs_with_hostname_tags["fqdn_enabled"]
        fqdn_enabled_mask = fqdn_enabled_col.notna() & fqdn_enabled_col.astype(bool)
        egress_vpcs_with_hostname_tags = egress_vpcs_with_hostname_tags[fqdn_enabled_mask]
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
            # Match by protocol, port, fqdn_mode and overlapping FQDNs
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
                    src_sg_ref = f"${{aviatrix_smart_group.{src_sg_name}.id}}"
                    dst_sg_ref = f"${{aviatrix_smart_group.{sg_name}.id}}"

                    action = "PERMIT" if fqdn_mode == "white" else "DENY"
                    policy_name = (
                        f"FQDN_{vpc_display_name}_{'permit' if fqdn_mode == 'white' else 'deny'}"
                    )

                    # Convert port to port_ranges format, handling special cases
                    if port == "ALL":
                        port_ranges = None  # No port restrictions for ALL
                    else:
                        port_ranges = self.translate_port_to_port_range([port]) if port else None

                    # Ensure protocol is properly formatted for DCF
                    dcf_protocol = protocol.upper()
                    if dcf_protocol == "ALL":
                        dcf_protocol = "ANY"

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
            hostname_policies_df = self.deduplicate_policy_names(hostname_policies_df)
            # Policies will get priorities assigned by the InternetPolicyBuilder
            hostname_policies_df = hostname_policies_df.reset_index(drop=True)

        logging.info(f"Created {len(hostname_policies_df)} hostname-based policies")
        return hostname_policies_df


class FQDNHandler:
    """Main handler class that orchestrates all FQDN processing."""

    def __init__(
        self,
        default_web_port_ranges: List[str],
        translate_port_to_port_range_func: Any,
        pretty_parse_vpc_name_func: Any,
        deduplicate_policy_names_func: Any,
        unsupported_fqdn_tracker: Optional[Any] = None,
    ) -> None:
        """
        Initialize the FQDN handler with required dependencies.

        Args:
            default_web_port_ranges: List of port ranges considered web traffic
            translate_port_to_port_range_func: Function to convert ports to DCF format
            pretty_parse_vpc_name_func: Function to clean VPC names
            deduplicate_policy_names_func: Function to deduplicate policy names
            unsupported_fqdn_tracker: Optional tracker for unsupported FQDN domains
        """
        self.validator = FQDNValidator()
        self.rule_processor = FQDNRuleProcessor(default_web_port_ranges)
        self.webgroup_builder = WebGroupBuilder(unsupported_fqdn_tracker)
        self.hostname_sg_builder = HostnameSmartGroupBuilder()
        self.policy_builder = FQDNPolicyBuilder(
            translate_port_to_port_range_func,
            pretty_parse_vpc_name_func,
            deduplicate_policy_names_func,
        )
        self.unsupported_fqdn_tracker = unsupported_fqdn_tracker

    def process_fqdn_rules(
        self, fqdn_tag_rule_df: pd.DataFrame, fqdn_df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Process FQDN rules and split them into webgroup and hostname categories.

        Args:
            fqdn_tag_rule_df: DataFrame containing FQDN tag rules
            fqdn_df: DataFrame containing FQDN configurations

        Returns:
            Tuple of (webgroup_rules, hostname_rules, unsupported_rules)
        """
        return self.rule_processor.eval_unsupported_webgroups(fqdn_tag_rule_df, fqdn_df)

    def build_webgroups(self, webgroup_rules_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build WebGroups from webgroup-compatible FQDN rules.

        Args:
            webgroup_rules_df: DataFrame containing webgroup-compatible rules

        Returns:
            DataFrame containing WebGroup configurations
        """
        return self.webgroup_builder.build_webgroup_df(webgroup_rules_df)

    def build_hostname_smartgroups(self, hostname_rules_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build hostname SmartGroups from hostname-compatible FQDN rules.

        Args:
            hostname_rules_df: DataFrame containing hostname-compatible rules

        Returns:
            DataFrame containing hostname SmartGroup configurations
        """
        return self.hostname_sg_builder.build_hostname_smartgroups(hostname_rules_df)

    def build_hostname_policies(
        self,
        gateways_df: pd.DataFrame,
        fqdn_df: pd.DataFrame,
        hostname_smartgroups_df: pd.DataFrame,
        hostname_rules_df: pd.DataFrame,
    ) -> pd.DataFrame:
        """
        Build DCF policies for hostname-based FQDN rules.

        Args:
            gateways_df: DataFrame containing gateway information
            fqdn_df: DataFrame containing FQDN configurations
            hostname_smartgroups_df: DataFrame containing hostname SmartGroups
            hostname_rules_df: DataFrame containing hostname rules

        Returns:
            DataFrame containing hostname-based DCF policies
        """
        return self.policy_builder.build_hostname_policies(
            gateways_df, fqdn_df, hostname_smartgroups_df, hostname_rules_df
        )

    def validate_domain(self, domain: str) -> bool:
        """
        Validate a single domain for DCF 8.0 compatibility.

        Args:
            domain: Domain to validate

        Returns:
            True if valid, False otherwise
        """
        return self.validator.validate_sni_domain_for_dcf(domain)

    def filter_domains(
        self, domains: List[str], context: Optional[str] = None
    ) -> Tuple[List[str], List[str]]:
        """
        Filter a list of domains for DCF 8.0 compatibility.

        Args:
            domains: List of domains to filter
            context: Context for logging (optional)

        Returns:
            Tuple of (valid_domains, invalid_domains)
        """
        return self.validator.filter_domains_for_dcf_compatibility(domains, context)
