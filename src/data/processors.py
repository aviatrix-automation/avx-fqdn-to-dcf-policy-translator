"""
Data processing module for the legacy-to-DCF policy translator.

Handles data cleaning, validation, and transformation operations.
"""

import logging
import re
from typing import Dict, Any, List, Tuple, Set
import pandas as pd

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from config import TranslationConfig, INVALID_CHARS_REPLACEMENT


class DataCleaner:
    """Handles data cleaning and normalization operations."""
    
    def __init__(self, config: TranslationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def remove_invalid_name_chars(self, df: pd.DataFrame, column: str) -> pd.DataFrame:
        """
        Remove or replace invalid characters from names for DCF compatibility.
        
        Args:
            df: DataFrame to clean
            column: Column name to clean
            
        Returns:
            DataFrame with cleaned names
        """
        if df.empty or column not in df.columns:
            return df
        
        df = df.copy()
        
        # Convert to string and strip whitespace
        df[column] = df[column].astype(str).str.strip()
        
        # Apply character replacements
        for invalid_char, replacement in INVALID_CHARS_REPLACEMENT.items():
            df[column] = df[column].str.replace(invalid_char, replacement, regex=False)
        
        # Handle double tildes first (specific pattern before individual tildes)
        df[column] = df[column].str.replace('~~', '_', regex=False)
        
        # Additional common replacements
        df[column] = df[column].str.replace('~', '_', regex=False)
        df[column] = df[column].str.replace('.', '_', regex=False)
        
        # Remove any remaining problematic characters (keep only alphanumeric, underscore, hyphen)
        df[column] = df[column].str.replace(r'[^\w\-]', '_', regex=True)
        
        # Collapse multiple underscores
        df[column] = df[column].str.replace(r'_{2,}', '_', regex=True)
        
        # Remove leading/trailing underscores
        df[column] = df[column].str.strip('_')
        
        self.logger.debug(f"Cleaned {column} column for DCF compatibility")
        return df
    
    def pretty_parse_vpc_name(self, df: pd.DataFrame, column: str) -> pd.Series:
        """
        Parse and clean VPC names for SmartGroup naming.
        
        Args:
            df: DataFrame containing VPC data
            column: Column containing VPC identifiers
            
        Returns:
            Series with cleaned VPC names
        """
        if df.empty or column not in df.columns:
            return pd.Series(dtype=str)
        
        temp_df = df.copy()
        temp_df = self.remove_invalid_name_chars(temp_df, column)
        return temp_df[column]


class PolicyCleaner:
    """Handles firewall policy cleaning and deduplication."""
    
    def __init__(self, config: TranslationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def remove_policy_duplicates(self, fw_policy_df: pd.DataFrame) -> pd.DataFrame:
        """
        Remove duplicate firewall policies and export removed duplicates for analysis.
        
        Args:
            fw_policy_df: DataFrame containing firewall policies
            
        Returns:
            DataFrame with duplicates removed
        """
        if fw_policy_df.empty:
            return fw_policy_df
        
        # Identify duplicates
        duplicate_cols = ['src_ip', 'dst_ip', 'protocol', 'port', 'action']
        duplicates = fw_policy_df.duplicated(subset=duplicate_cols)
        
        # Export removed duplicates if any exist
        if duplicates.any():
            removed_duplicates = fw_policy_df[duplicates].copy()
            if self.config.enable_debug:
                debug_file = self.config.get_debug_file_path('removed_duplicates')
                removed_duplicates.to_csv(debug_file, index=False)
                self.logger.info(f"Exported {len(removed_duplicates)} duplicate policies to {debug_file}")
        
        # Remove duplicates
        cleaned_df = fw_policy_df.drop_duplicates(subset=duplicate_cols)
        
        self.logger.info(f"Removed {len(fw_policy_df) - len(cleaned_df)} duplicate policies")
        return cleaned_df
    
    def deduplicate_policy_names(self, policies_df: pd.DataFrame) -> pd.DataFrame:
        """
        Ensure policy names are unique by adding suffixes where needed.
        
        Args:
            policies_df: DataFrame containing policies with names
            
        Returns:
            DataFrame with unique policy names
        """
        if policies_df.empty or 'name' not in policies_df.columns:
            return policies_df
        
        df = policies_df.copy()
        
        # Track name counts
        name_counts = {}
        new_names = []
        
        for name in df['name']:
            if name not in name_counts:
                name_counts[name] = 0
                new_names.append(name)
            else:
                name_counts[name] += 1
                new_names.append(f"{name}_{name_counts[name]}")
        
        df['name'] = new_names
        
        duplicates_fixed = len(df) - len(set(new_names))
        if duplicates_fixed > 0:
            self.logger.info(f"Fixed {duplicates_fixed} duplicate policy names")
        
        return df


class FirewallTagProcessor:
    """Processes firewall tags and related operations."""
    
    def __init__(self, config: TranslationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def eval_unused_fw_tags(self, fw_policy_df: pd.DataFrame, fw_tag_df: pd.DataFrame) -> pd.DataFrame:
        """
        Remove unused firewall tags that are not referenced in any policies.
        
        Args:
            fw_policy_df: DataFrame containing firewall policies
            fw_tag_df: DataFrame containing firewall tags
            
        Returns:
            DataFrame with unused tags removed
        """
        if fw_tag_df.empty:
            return fw_tag_df
        
        if fw_policy_df.empty:
            self.logger.warning("No firewall policies found - all tags considered unused")
            return pd.DataFrame(columns=fw_tag_df.columns)
        
        # Get all referenced IPs from policies
        unique_src_dst = pd.concat([fw_policy_df['src_ip'], fw_policy_df['dst_ip']]).unique()
        
        # Find unused tags
        unused_tags = set(fw_tag_df['firewall_tag']) - set(unique_src_dst)
        
        if unused_tags:
            self.logger.info(f"Removing {len(unused_tags)} unused firewall tags: {unused_tags}")
            fw_tag_df_cleaned = fw_tag_df[~fw_tag_df['firewall_tag'].isin(unused_tags)].copy()
        else:
            fw_tag_df_cleaned = fw_tag_df.copy()
        
        return fw_tag_df_cleaned
    
    def eval_single_cidr_tag_match(self, fw_policy_df: pd.DataFrame, fw_tag_df: pd.DataFrame) -> pd.DataFrame:
        """
        Replace single CIDR references with their corresponding tag names.
        
        Args:
            fw_policy_df: DataFrame containing firewall policies
            fw_tag_df: DataFrame containing firewall tags
            
        Returns:
            DataFrame with CIDR references replaced by tag names
        """
        if fw_policy_df.empty or fw_tag_df.empty:
            return fw_policy_df
        
        # Find single CIDR tags
        single_cidr_tags = fw_tag_df[fw_tag_df['cidr_list'].apply(
            lambda x: isinstance(x, dict))].copy()
        
        if single_cidr_tags.empty:
            return fw_policy_df
        
        # Create mapping from CIDR to tag name
        single_cidr_tags['cidr'] = single_cidr_tags['cidr_list'].apply(lambda x: x['cidr'])
        cidr_to_tag_map = dict(zip(single_cidr_tags['cidr'], single_cidr_tags['firewall_tag']))
        
        self.logger.info(f"Found {len(cidr_to_tag_map)} single CIDR tags for replacement")
        self.logger.debug(f"CIDR to tag mapping: {cidr_to_tag_map}")
        
        # Replace CIDRs with tag names in policies
        df = fw_policy_df.copy()
        df['src_ip'] = df['src_ip'].apply(lambda x: cidr_to_tag_map.get(x, x))
        df['dst_ip'] = df['dst_ip'].apply(lambda x: cidr_to_tag_map.get(x, x))
        
        return df


class StatelessPolicyAnalyzer:
    """Analyzes policies for stateless translation issues."""
    
    def __init__(self, config: TranslationConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def eval_stateless_alerts(self, fw_policy_df: pd.DataFrame) -> pd.DataFrame:
        """
        Identify policies that may cause stateless translation issues.
        
        Args:
            fw_policy_df: DataFrame containing firewall policies
            
        Returns:
            DataFrame containing policies with potential issues
        """
        if fw_policy_df.empty:
            return pd.DataFrame()
        
        self.logger.info("Evaluating policies for stateless translation issues")
        
        # Find problematic policies: UDP or ANY protocol with no port and allow/force-drop action
        stateless_alerts = fw_policy_df[
            ((fw_policy_df['protocol'] == 'udp') | (fw_policy_df['protocol'] == 'all')) &
            (fw_policy_df['port'] == '') &
            ((fw_policy_df['action'] == 'allow') | (fw_policy_df['action'] == 'force-drop'))
        ].copy()
        
        if not stateless_alerts.empty:
            # Export issues if debug mode is enabled
            if self.config.enable_debug:
                issues_file = self.config.debug_dir / 'stateless_rule_issues.csv'
                stateless_alerts.to_csv(issues_file, index=False)
                self.logger.warning(f"Exported {len(stateless_alerts)} stateless policy issues to {issues_file}")
        
        self.logger.info(f"Found {len(stateless_alerts)} policies with potential stateless issues")
        return stateless_alerts


class DataProcessor:
    """Main data processor that orchestrates all processing operations."""
    
    def __init__(self, config: TranslationConfig):
        self.config = config
        self.cleaner = DataCleaner(config)
        self.policy_cleaner = PolicyCleaner(config)
        self.fw_tag_processor = FirewallTagProcessor(config)
        self.stateless_analyzer = StatelessPolicyAnalyzer(config)
        self.logger = logging.getLogger(__name__)
    
    def process_firewall_policies(self, fw_policy_df: pd.DataFrame, fw_tag_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Process firewall policies through the complete cleaning pipeline.
        
        Args:
            fw_policy_df: Raw firewall policies DataFrame
            fw_tag_df: Raw firewall tags DataFrame
            
        Returns:
            Tuple of (cleaned_policies_df, cleaned_tags_df, stateless_alerts_df)
        """
        self.logger.info("Processing firewall policies through cleaning pipeline")
        
        # Analyze for stateless issues first (on raw data)
        stateless_alerts = self.stateless_analyzer.eval_stateless_alerts(fw_policy_df)
        
        # Clean unused tags
        cleaned_tags = self.fw_tag_processor.eval_unused_fw_tags(fw_policy_df, fw_tag_df)
        
        # Replace single CIDR references with tags
        processed_policies = self.fw_tag_processor.eval_single_cidr_tag_match(fw_policy_df, cleaned_tags)
        
        # Remove duplicate policies
        final_policies = self.policy_cleaner.remove_policy_duplicates(processed_policies)
        
        # Export debug data if enabled
        if self.config.enable_debug:
            debug_file = self.config.get_debug_file_path('clean_policies')
            final_policies.to_csv(debug_file, index=False)
            self.logger.debug(f"Exported cleaned policies to {debug_file}")
        
        self.logger.info(f"Policy processing complete: {len(final_policies)} clean policies, {len(cleaned_tags)} tags")
        return final_policies, cleaned_tags, stateless_alerts
    
    def clean_names_for_dcf(self, df: pd.DataFrame, name_column: str) -> pd.DataFrame:
        """
        Clean names in a DataFrame for DCF compatibility.
        
        Args:
            df: DataFrame to clean
            name_column: Name of the column containing names to clean
            
        Returns:
            DataFrame with cleaned names
        """
        return self.cleaner.remove_invalid_name_chars(df, name_column)
