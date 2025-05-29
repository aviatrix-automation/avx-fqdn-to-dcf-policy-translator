"""
Policy validation module for legacy firewall policy analysis.

This module provides validators for analyzing legacy firewall policies
and identifying potential issues during translation to DCF.
"""

import logging
import pandas as pd
from typing import Dict, List, Tuple, Any, Set
from dataclasses import dataclass

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))


@dataclass
class ValidationResult:
    """Result of policy validation containing issues and statistics."""
    total_policies: int
    issues_found: int
    stateless_issues: int
    unused_tags: Set[str]
    single_cidr_tags: Dict[str, str]
    duplicate_policies: int
    validation_warnings: List[str]
    validation_errors: List[str]


class PolicyValidator:
    """Validates legacy firewall policies and identifies translation issues."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def eval_stateless_alerts(self, fw_policy_df: pd.DataFrame) -> pd.DataFrame:
        """
        Evaluate stateless policy translation issues.
        
        Identifies UDP or ANY protocol policies that have "force-drop" and no port defined,
        or policies without specific ports that might create overly permissive rules.
        
        Args:
            fw_policy_df: DataFrame containing firewall policy data
            
        Returns:
            DataFrame containing problematic stateless policies
        """
        self.logger.info("Evaluating Stateless policy translation issues")
        
        stateless_alerts = fw_policy_df[
            ((fw_policy_df['protocol'] == 'udp') | (fw_policy_df['protocol'] == 'all')) & 
            (fw_policy_df['port'] == '') & 
            ((fw_policy_df['action'] == 'allow') | (fw_policy_df['action'] == 'force-drop'))
        ].copy()
        
        self.logger.info(f"Stateless Policy Issues: {len(stateless_alerts)}")
        
        if len(stateless_alerts) > 0:
            self.logger.warning(
                f"Found {len(stateless_alerts)} stateless policy issues that may cause "
                "bi-directional drops or overly permissive rules"
            )
        
        return stateless_alerts
    
    def eval_unused_fw_tags(self, fw_policy_df: pd.DataFrame, 
                           fw_tag_df: pd.DataFrame) -> Tuple[pd.DataFrame, Set[str]]:
        """
        Identify and filter out unused firewall tags.
        
        Args:
            fw_policy_df: DataFrame containing firewall policies
            fw_tag_df: DataFrame containing firewall tags
            
        Returns:
            Tuple of (filtered_fw_tag_df, set_of_unused_tags)
        """
        self.logger.info("Evaluating unused firewall tags")
        
        # Get all source and destination IPs used in policies
        unique_src_dst = pd.concat([
            fw_policy_df['src_ip'], 
            fw_policy_df['dst_ip']
        ]).unique()
        
        # Find unused tags
        unused_tags = set(fw_tag_df['firewall_tag']) - set(unique_src_dst)
        
        self.logger.info(f"Found {len(unused_tags)} unused firewall tags")
        if unused_tags:
            self.logger.debug(f"Unused tags: {unused_tags}")
        
        # Remove unused tags
        fw_tag_df_filtered = fw_tag_df.drop(
            fw_tag_df[fw_tag_df['firewall_tag'].isin(unused_tags)].index
        ).copy()
        
        return fw_tag_df_filtered, unused_tags
    
    def eval_single_cidr_tag_match(self, fw_policy_df: pd.DataFrame, 
                                  fw_tag_df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, str]]:
        """
        Check for single CIDR tags and replace policy references with equivalent tags.
        
        Args:
            fw_policy_df: DataFrame containing firewall policies
            fw_tag_df: DataFrame containing firewall tags
            
        Returns:
            Tuple of (updated_fw_policy_df, single_cidr_mapping)
        """
        self.logger.info("Evaluating Single CIDR firewall tags")
        
        # Find tags that contain only a single CIDR
        single_cidr_tags = fw_tag_df[
            fw_tag_df['cidr_list'].apply(lambda x: isinstance(x, dict))
        ].copy()
        
        if not single_cidr_tags.empty:
            single_cidr_tags['cidr'] = single_cidr_tags['cidr_list'].apply(
                lambda x: x.get('cidr', '') if isinstance(x, dict) else ''
            )
            single_cidr_mapping = dict(
                zip(single_cidr_tags['cidr'], single_cidr_tags['firewall_tag'])
            )
        else:
            single_cidr_mapping = {}
        
        self.logger.info(
            f"Found {len(single_cidr_mapping)} single CIDR firewall tags. "
            "Attempting to replace them with matching named tags."
        )
        
        if single_cidr_mapping:
            self.logger.debug(f"Single CIDR mappings: {single_cidr_mapping}")
            
            # Update policy references
            fw_policy_df_updated = fw_policy_df.copy()
            fw_policy_df_updated['src_ip'] = fw_policy_df_updated['src_ip'].apply(
                lambda x: single_cidr_mapping.get(x, x)
            )
            fw_policy_df_updated['dst_ip'] = fw_policy_df_updated['dst_ip'].apply(
                lambda x: single_cidr_mapping.get(x, x)
            )
            
            return fw_policy_df_updated, single_cidr_mapping
        
        return fw_policy_df, single_cidr_mapping
    
    def identify_duplicate_policies(self, fw_policy_df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
        """
        Identify and remove duplicate firewall policies.
        
        Args:
            fw_policy_df: DataFrame containing firewall policies
            
        Returns:
            Tuple of (deduplicated_df, number_of_duplicates)
        """
        self.logger.info("Evaluating duplicate policies")
        
        initial_count = len(fw_policy_df)
        
        # Identify duplicates based on key policy fields
        duplicate_mask = fw_policy_df.duplicated(
            subset=['src_ip', 'dst_ip', 'protocol', 'port', 'action'],
            keep='first'
        )
        
        duplicates_count = duplicate_mask.sum()
        
        if duplicates_count > 0:
            self.logger.info(f"Found {duplicates_count} duplicate policies out of {initial_count}")
            
            # Remove duplicates
            deduplicated_df = fw_policy_df[~duplicate_mask].copy()
        else:
            self.logger.info("No duplicate policies found")
            deduplicated_df = fw_policy_df.copy()
        
        return deduplicated_df, duplicates_count
    
    def validate_protocol_port_combinations(self, fw_policy_df: pd.DataFrame) -> List[str]:
        """
        Validate protocol and port combinations for potential issues.
        
        Args:
            fw_policy_df: DataFrame containing firewall policies
            
        Returns:
            List of validation warning messages
        """
        warnings = []
        
        # Check for TCP policies with invalid port ranges
        tcp_policies = fw_policy_df[fw_policy_df['protocol'].str.lower() == 'tcp']
        for idx, policy in tcp_policies.iterrows():
            port = str(policy.get('port', ''))
            if port and port != 'any' and port != 'all':
                try:
                    # Basic port range validation
                    if '-' in port:
                        start, end = port.split('-', 1)
                        start_port = int(start)
                        end_port = int(end)
                        if start_port > end_port or start_port < 1 or end_port > 65535:
                            warnings.append(f"Invalid TCP port range '{port}' in policy {idx}")
                    else:
                        port_num = int(port)
                        if port_num < 1 or port_num > 65535:
                            warnings.append(f"Invalid TCP port '{port}' in policy {idx}")
                except ValueError:
                    warnings.append(f"Non-numeric TCP port '{port}' in policy {idx}")
        
        # Check for ICMP policies with ports (should not have ports)
        icmp_policies = fw_policy_df[fw_policy_df['protocol'].str.lower() == 'icmp']
        icmp_with_ports = icmp_policies[icmp_policies['port'].notna() & (icmp_policies['port'] != '')]
        if not icmp_with_ports.empty:
            warnings.append(f"Found {len(icmp_with_ports)} ICMP policies with port specifications")
        
        return warnings
    
    def validate_ip_addresses(self, fw_policy_df: pd.DataFrame, 
                             fw_tag_df: pd.DataFrame) -> List[str]:
        """
        Validate IP addresses and CIDR blocks in policies and tags.
        
        Args:
            fw_policy_df: DataFrame containing firewall policies
            fw_tag_df: DataFrame containing firewall tags
            
        Returns:
            List of validation warning messages
        """
        warnings = []
        
        # Import here to avoid circular imports
        from utils.data_processing import is_ipv4
        
        # Check source and destination IPs in policies
        for column in ['src_ip', 'dst_ip']:
            for idx, policy in fw_policy_df.iterrows():
                ip_value = policy.get(column, '')
                if ip_value and not is_ipv4(ip_value):
                    # Check if it's a tag reference
                    if ip_value not in fw_tag_df['firewall_tag'].values:
                        warnings.append(f"Invalid IP/CIDR '{ip_value}' in {column} of policy {idx}")
        
        # Check CIDR blocks in firewall tags
        for idx, tag in fw_tag_df.iterrows():
            cidr_list = tag.get('cidr_list', [])
            tag_name = tag.get('firewall_tag', f'tag_{idx}')
            
            if isinstance(cidr_list, list):
                for cidr_entry in cidr_list:
                    if isinstance(cidr_entry, dict) and 'cidr' in cidr_entry:
                        cidr = cidr_entry['cidr']
                        if not is_ipv4(cidr):
                            warnings.append(f"Invalid CIDR '{cidr}' in tag '{tag_name}'")
            elif isinstance(cidr_list, dict) and 'cidr' in cidr_list:
                cidr = cidr_list['cidr']
                if not is_ipv4(cidr):
                    warnings.append(f"Invalid CIDR '{cidr}' in tag '{tag_name}'")
        
        return warnings
    
    def perform_comprehensive_validation(self, fw_policy_df: pd.DataFrame, 
                                       fw_tag_df: pd.DataFrame) -> ValidationResult:
        """
        Perform comprehensive validation of firewall policies and tags.
        
        Args:
            fw_policy_df: DataFrame containing firewall policies
            fw_tag_df: DataFrame containing firewall tags
            
        Returns:
            ValidationResult containing all validation findings
        """
        self.logger.info("Starting comprehensive policy validation")
        
        # Handle empty DataFrames
        if fw_policy_df.empty:
            self.logger.warning("No firewall policies to validate")
            return ValidationResult(
                total_policies=0,
                issues_found=0,
                stateless_issues=0,
                unused_tags=set(),
                single_cidr_tags={},
                duplicate_policies=0,
                validation_warnings=["No firewall policies found"],
                validation_errors=[]
            )
        
        initial_policy_count = len(fw_policy_df)
        validation_warnings = []
        validation_errors = []
        
        # Stateless policy issues
        stateless_issues_df = self.eval_stateless_alerts(fw_policy_df)
        stateless_issues_count = len(stateless_issues_df)
        
        # Unused tags
        fw_tag_df_filtered, unused_tags = self.eval_unused_fw_tags(fw_policy_df, fw_tag_df)
        
        # Single CIDR tag matching
        fw_policy_df_updated, single_cidr_mapping = self.eval_single_cidr_tag_match(
            fw_policy_df, fw_tag_df_filtered
        )
        
        # Duplicate policies
        fw_policy_df_final, duplicate_count = self.identify_duplicate_policies(fw_policy_df_updated)
        
        # Protocol/port validation
        protocol_warnings = self.validate_protocol_port_combinations(fw_policy_df_final)
        validation_warnings.extend(protocol_warnings)
        
        # IP address validation
        ip_warnings = self.validate_ip_addresses(fw_policy_df_final, fw_tag_df_filtered)
        validation_warnings.extend(ip_warnings)
        
        total_issues = stateless_issues_count + len(unused_tags) + duplicate_count + len(validation_warnings)
        
        self.logger.info(f"Validation completed: {total_issues} total issues found")
        
        return ValidationResult(
            total_policies=initial_policy_count,
            issues_found=total_issues,
            stateless_issues=stateless_issues_count,
            unused_tags=unused_tags,
            single_cidr_tags=single_cidr_mapping,
            duplicate_policies=duplicate_count,
            validation_warnings=validation_warnings,
            validation_errors=validation_errors
        )
