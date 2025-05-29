"""
Policy translation logic for the legacy-to-DCF policy translator.

This module handles the translation of legacy firewall policies to DCF format,
including L4 policies, internet policies, catch-all policies, and hostname policies.
"""

import logging
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional

from config.defaults import POLICY_PRIORITIES
from utils.data_processing import is_ipv4, translate_port_to_port_range
from data.processors import DataCleaner
from config import TranslationConfig


class PolicyBuilder:
    """Base class for building DCF policies from legacy configurations."""
    
    def __init__(self, internet_sg_id: str, anywhere_sg_id: str):
        self.internet_sg_id = internet_sg_id
        self.anywhere_sg_id = anywhere_sg_id
    
    def create_smartgroup_reference(self, sg_name: str) -> str:
        """Create Terraform reference for a SmartGroup."""
        return f"${{aviatrix_smart_group.{sg_name}.id}}"


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
        consolidated_df = fw_policy_df.groupby([
            'src_ip', 'dst_ip', 'protocol', 'action', 'log_enabled'
        ])['port'].apply(list).reset_index()
        
        # Convert ports to port ranges
        consolidated_df['port_ranges'] = consolidated_df['port'].apply(
            translate_port_to_port_range
        )
        
        # Update source and destination to match SmartGroup naming
        for column in ['src_ip', 'dst_ip']:
            consolidated_df[column] = consolidated_df[column].apply(
                lambda x: 'cidr_' + x if is_ipv4(x) else x
            )
            consolidated_df = self.cleaner.remove_invalid_name_chars(consolidated_df, column)
        
        # Create SmartGroup references
        consolidated_df['src_smart_groups'] = consolidated_df['src_ip'].apply(
            lambda x: [self.create_smartgroup_reference(x)]
        )
        consolidated_df['dst_smart_groups'] = consolidated_df['dst_ip'].apply(
            lambda x: [self.create_smartgroup_reference(x)]
        )
        
        # Convert actions and other fields to DCF format
        consolidated_df['action'] = consolidated_df['action'].apply(
            lambda x: 'PERMIT' if x == 'allow' else 'DENY'
        )
        consolidated_df['logging'] = consolidated_df['log_enabled'].apply(
            lambda x: False if x == 'FALSE' else True
        )
        consolidated_df['protocol'] = consolidated_df['protocol'].str.upper()
        consolidated_df.loc[consolidated_df['protocol'] == '', 'protocol'] = 'ANY'
        consolidated_df['protocol'] = consolidated_df['protocol'].str.replace('ALL', 'ANY')
        
        # Generate policy names
        consolidated_df['name'] = consolidated_df.apply(
            lambda row: f"{row['src_ip']}_{row['dst_ip']}", axis=1
        )
        
        # Select final columns
        policy_df = consolidated_df[[
            'src_smart_groups', 'dst_smart_groups', 'action', 'logging', 
            'protocol', 'name', 'port_ranges'
        ]]
        
        # Deduplicate policy names and add priorities
        policy_df = self._deduplicate_policy_names(policy_df)
        policy_df = self._add_priorities(policy_df, POLICY_PRIORITIES['l4_policies'])
        
        logging.info(f"Created {len(policy_df)} L4 DCF policies")
        return policy_df
    
    def _deduplicate_policy_names(self, policies_df: pd.DataFrame) -> pd.DataFrame:
        """Deduplicate policy names by adding numeric suffixes."""
        if len(policies_df) == 0:
            return policies_df
            
        name_counts = {}
        new_names = []
        
        for name in policies_df['name']:
            if name in name_counts:
                name_counts[name] += 1
                new_names.append(f"{name}_{name_counts[name]}")
            else:
                name_counts[name] = 0
                new_names.append(name)
        
        policies_df = policies_df.copy()
        policies_df['name'] = new_names
        return policies_df
    
    def _add_priorities(self, policies_df: pd.DataFrame, base_priority: int) -> pd.DataFrame:
        """Add priority values to policies."""
        policies_df = policies_df.reset_index(drop=True)
        policies_df.index = policies_df.index + base_priority
        policies_df['priority'] = policies_df.index
        return policies_df


class InternetPolicyBuilder(PolicyBuilder):
    """Builds internet egress policies for FQDN traffic."""
    
    def __init__(self, internet_sg_id: str, anywhere_sg_id: str, 
                 default_web_port_ranges: List[str], any_webgroup_id: str):
        super().__init__(internet_sg_id, anywhere_sg_id)
        self.default_web_port_ranges = default_web_port_ranges
        self.any_webgroup_id = any_webgroup_id
        self.cleaner = DataCleaner(TranslationConfig())
    
    def build_internet_policies(self, gateways_df: pd.DataFrame, fqdn_df: pd.DataFrame,
                               webgroups_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build internet egress policies for FQDN traffic.
        
        Args:
            gateways_df: DataFrame with gateway details
            fqdn_df: DataFrame with FQDN tag configurations
            webgroups_df: DataFrame with WebGroup configurations
            
        Returns:
            DataFrame with internet egress policies
        """
        logging.info("Building internet egress policies")
        
        # Get egress VPCs (non-HAGW with NAT enabled)
        egress_vpcs = self._get_egress_vpcs(gateways_df)
        if len(egress_vpcs) == 0:
            logging.info("No egress VPCs found")
            return pd.DataFrame()
        
        # Process FQDN tags and clean disabled tags
        egress_vpcs = self._process_fqdn_tags(egress_vpcs, fqdn_df)
        
        # Build different types of internet policies
        policy_dataframes = []
        
        # 1. FQDN tag-specific policies (webgroup-based)
        fqdn_policies = self._build_fqdn_tag_policies(egress_vpcs, fqdn_df, webgroups_df)
        if len(fqdn_policies) > 0:
            policy_dataframes.append(fqdn_policies)
        
        # 2. Default policies for FQDN tags
        default_policies = self._build_fqdn_default_policies(egress_vpcs, fqdn_df)
        if len(default_policies) > 0:
            policy_dataframes.append(default_policies)
        
        # 3. Discovery mode policies
        discovery_policies = self._build_discovery_policies(egress_vpcs)
        if len(discovery_policies) > 0:
            policy_dataframes.extend(discovery_policies)
        
        # 4. NAT-only policies
        nat_only_policies = self._build_nat_only_policies(egress_vpcs)
        if len(nat_only_policies) > 0:
            policy_dataframes.append(nat_only_policies)
        
        # Merge all policies
        if not policy_dataframes:
            logging.info("No internet policies created")
            return pd.DataFrame()
        
        internet_policies = pd.concat(policy_dataframes, ignore_index=True)
        
        # Sort and prioritize policies
        internet_policies = self._sort_and_prioritize_policies(internet_policies)
        
        logging.info(f"Created {len(internet_policies)} internet policies")
        return internet_policies
    
    def _get_egress_vpcs(self, gateways_df: pd.DataFrame) -> pd.DataFrame:
        """Get egress VPCs (non-HAGW with NAT enabled)."""
        egress_vpcs = gateways_df[
            (gateways_df['is_hagw'] == 'no') & 
            (gateways_df['enable_nat'] == 'yes')
        ].drop_duplicates(subset=['vpc_id', 'vpc_region', 'account_name'])
        
        return egress_vpcs[[
            'fqdn_tags', 'stateful_fw', 'egress_control', 'vpc_name', 'vpc_id'
        ]]
    
    def _process_fqdn_tags(self, egress_vpcs: pd.DataFrame, fqdn_df: pd.DataFrame) -> pd.DataFrame:
        """Process and clean FQDN tags for egress VPCs."""
        from ..data.processors import pretty_parse_vpc_name
        
        egress_vpcs['src_smart_groups'] = egress_vpcs['vpc_id']
        egress_vpcs['src_smart_groups'] = pretty_parse_vpc_name(egress_vpcs, "src_smart_groups")
        egress_vpcs = self.cleaner.remove_invalid_name_chars(egress_vpcs, "src_smart_groups")
        egress_vpcs['src_smart_groups'] = egress_vpcs['src_smart_groups'].apply(
            lambda x: self.create_smartgroup_reference(x)
        )
        
        # Clean up disabled tag references
        disabled_tag_names = list(fqdn_df[fqdn_df['fqdn_enabled'] == False]['fqdn_tag'])
        if disabled_tag_names:
            egress_vpcs_with_disabled = egress_vpcs[egress_vpcs['fqdn_tags'].apply(
                lambda x: any(item in disabled_tag_names for item in x)
            )]
            if len(egress_vpcs_with_disabled) > 0:
                logging.warning(f"{len(egress_vpcs_with_disabled)} VPCs have disabled FQDN tags. "
                              f"Policies for these tags will be ignored.")
            
            egress_vpcs['fqdn_tags'] = egress_vpcs['fqdn_tags'].apply(
                lambda x: [item for item in x if item not in disabled_tag_names]
            )
        
        return egress_vpcs
    
    def _build_fqdn_tag_policies(self, egress_vpcs: pd.DataFrame, fqdn_df: pd.DataFrame,
                                webgroups_df: pd.DataFrame) -> pd.DataFrame:
        """Build FQDN tag-specific policies using WebGroups."""
        egress_vpcs_with_enabled_tags = egress_vpcs.explode("fqdn_tags").rename(
            columns={'fqdn_tags': 'fqdn_tag'}
        ).merge(fqdn_df, on="fqdn_tag", how='left')
        
        egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags[
            egress_vpcs_with_enabled_tags['fqdn_enabled'] == True
        ]
        egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags.rename(
            columns={'fqdn_tag': 'fqdn_tag_name'}
        )
        
        fqdn_tag_policies = egress_vpcs_with_enabled_tags.merge(
            webgroups_df, on=['fqdn_tag_name', 'fqdn_mode'], how='left'
        )
        
        # Create WebGroup references
        fqdn_tag_policies['web_groups'] = fqdn_tag_policies['name'].apply(
            lambda x: f"${{aviatrix_web_group.{x}.id}}" if pd.notna(x) else None
        )
        
        # Group by VPC and FQDN configuration
        fqdn_tag_policies = fqdn_tag_policies.groupby([
            'src_smart_groups', 'vpc_name', 'protocol', 'port', 'fqdn_mode'
        ])['web_groups'].apply(list).reset_index()
        
        fqdn_tag_policies['src_smart_groups'] = fqdn_tag_policies['src_smart_groups'].apply(lambda x: [x])
        fqdn_tag_policies['dst_smart_groups'] = fqdn_tag_policies.apply(
            lambda x: [self.internet_sg_id], axis=1
        )
        fqdn_tag_policies['action'] = fqdn_tag_policies['fqdn_mode'].apply(
            lambda x: 'PERMIT' if x == 'white' else 'DENY'
        )
        fqdn_tag_policies['port_ranges'] = fqdn_tag_policies['port'].apply(
            lambda x: translate_port_to_port_range([x])
        )
        fqdn_tag_policies['logging'] = True
        fqdn_tag_policies['protocol'] = fqdn_tag_policies['protocol'].str.upper()
        fqdn_tag_policies['name'] = fqdn_tag_policies.apply(
            lambda row: f"Egress_{row['vpc_name']}_{'permit' if row['fqdn_mode'] == 'white' else 'deny'}",
            axis=1
        )
        
        return fqdn_tag_policies[[
            'src_smart_groups', 'dst_smart_groups', 'action', 'port_ranges',
            'logging', 'protocol', 'name', 'web_groups'
        ]]
    
    def _build_fqdn_default_policies(self, egress_vpcs: pd.DataFrame, fqdn_df: pd.DataFrame) -> pd.DataFrame:
        """Build default policies for FQDN tags based on default action."""
        egress_vpcs_with_enabled_tags = egress_vpcs.explode("fqdn_tags").rename(
            columns={'fqdn_tags': 'fqdn_tag'}
        ).merge(fqdn_df, on="fqdn_tag", how='left')
        
        egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags[
            egress_vpcs_with_enabled_tags['fqdn_enabled'] == True
        ]
        
        fqdn_tag_default_policies = egress_vpcs_with_enabled_tags.groupby(['fqdn_mode'])[
            'src_smart_groups'
        ].apply(list).reset_index()
        
        fqdn_tag_default_policies['dst_smart_groups'] = fqdn_tag_default_policies.apply(
            lambda x: [self.internet_sg_id], axis=1
        )
        fqdn_tag_default_policies['logging'] = True
        fqdn_tag_default_policies['protocol'] = "ANY"
        fqdn_tag_default_policies['port_ranges'] = None
        fqdn_tag_default_policies['web_groups'] = None
        fqdn_tag_default_policies['action'] = fqdn_tag_default_policies['fqdn_mode'].apply(
            lambda x: 'DENY' if x == 'white' else 'PERMIT'
        )
        fqdn_tag_default_policies['name'] = fqdn_tag_default_policies['fqdn_mode'].apply(
            lambda x: 'Egress-Permit-Default' if x == 'white' else 'Egress-Deny-Default'
        )
        
        return fqdn_tag_default_policies.drop(columns='fqdn_mode')
    
    def _build_discovery_policies(self, egress_vpcs: pd.DataFrame) -> List[pd.DataFrame]:
        """Build discovery mode policies for L7 and L4 traffic."""
        egress_vpcs_with_discovery = egress_vpcs[
            egress_vpcs['fqdn_tags'].astype(str).str.contains('-discovery')
        ]
        
        if egress_vpcs_with_discovery.empty:
            return []
        
        discovery_policies = []
        
        # L7 Discovery policy (web traffic with any webgroup)
        discovery_l7 = pd.DataFrame([{
            'src_smart_groups': list(egress_vpcs_with_discovery['src_smart_groups']),
            'dst_smart_groups': [self.internet_sg_id],
            'action': 'PERMIT',
            'logging': True,
            'protocol': 'TCP',
            'name': 'Egress-Discovery-L7',
            'port_ranges': translate_port_to_port_range(self.default_web_port_ranges),
            'web_groups': [self.any_webgroup_id]
        }])
        discovery_policies.append(discovery_l7)
        
        # L4 Discovery policy (all other traffic)
        discovery_l4 = pd.DataFrame([{
            'src_smart_groups': list(egress_vpcs_with_discovery['src_smart_groups']),
            'dst_smart_groups': [self.internet_sg_id],
            'action': 'PERMIT',
            'logging': True,
            'protocol': 'ANY',
            'name': 'Egress-Discovery-L4',
            'port_ranges': None,
            'web_groups': None
        }])
        discovery_policies.append(discovery_l4)
        
        return discovery_policies
    
    def _build_nat_only_policies(self, egress_vpcs: pd.DataFrame) -> pd.DataFrame:
        """Build policies for egress VPCs that only have NAT and no FQDN tags."""
        egress_vpcs_with_nat_only = egress_vpcs[
            egress_vpcs['fqdn_tags'].astype(str) == '[]'
        ]
        
        if egress_vpcs_with_nat_only.empty:
            return pd.DataFrame()
        
        nat_only_policies = pd.DataFrame([{
            'src_smart_groups': list(egress_vpcs_with_nat_only['src_smart_groups']),
            'dst_smart_groups': [self.internet_sg_id],
            'action': 'PERMIT',
            'logging': True,
            'protocol': 'ANY',
            'name': 'Egress-Allow-All',
            'port_ranges': None,
            'web_groups': None
        }])
        
        return nat_only_policies
    
    def _sort_and_prioritize_policies(self, internet_policies: pd.DataFrame) -> pd.DataFrame:
        """Sort policies and assign priorities."""
        def get_policy_priority(row):
            web_groups = row['web_groups']
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
        
        internet_policies['sort_priority'] = internet_policies.apply(get_policy_priority, axis=1)
        internet_policies = internet_policies.sort_values(['sort_priority']).drop(columns=['sort_priority'])
        internet_policies = internet_policies.reset_index(drop=True)
        
        # Deduplicate policy names
        internet_policies = self._deduplicate_policy_names(internet_policies)
        
        # Add priorities (internet policies start at 2000)
        internet_policies.index = internet_policies.index + POLICY_PRIORITIES['internet_policies']
        internet_policies['priority'] = internet_policies.index
        
        return internet_policies


class CatchAllPolicyBuilder(PolicyBuilder):
    """Builds catch-all policies based on VPC default policies."""
    
    def __init__(self, internet_sg_id: str, anywhere_sg_id: str, global_catch_all_action: str):
        super().__init__(internet_sg_id, anywhere_sg_id)
        self.global_catch_all_action = global_catch_all_action
        self.cleaner = DataCleaner(TranslationConfig())
    
    def build_catch_all_policies(self, gateways_df: pd.DataFrame, 
                                firewall_df: pd.DataFrame) -> pd.DataFrame:
        """
        Build catch-all policies based on VPC default firewall policies.
        
        Args:
            gateways_df: DataFrame with gateway details
            firewall_df: DataFrame with firewall default policies
            
        Returns:
            DataFrame with catch-all policies
        """
        logging.info("Building catch-all policies")
        
        # Remove HAGWs
        gateways_df = gateways_df[gateways_df['is_hagw'] == "no"]
        
        # Enrich gateway details with FW default policy
        if len(firewall_df) > 0:
            vpcs_and_fw = gateways_df.merge(
                firewall_df, left_on="vpc_name", right_on="gw_name", how="left"
            )
        else:
            vpcs_and_fw = gateways_df.copy()
            vpcs_and_fw['base_policy'] = np.nan
        
        # Sort by VPCs with known policies, then remove duplicate VPCs
        vpcs_and_fw = vpcs_and_fw.sort_values(['base_policy']).drop_duplicates(
            subset=['vpc_id'], keep='first'
        )
        vpcs_and_fw['base_policy'] = vpcs_and_fw['base_policy'].fillna('unknown')
        
        # Prepare SmartGroup column naming
        vpcs_and_fw['smart_groups'] = vpcs_and_fw['vpc_id']
        
        from ..data.processors import pretty_parse_vpc_name
        vpcs_and_fw['smart_groups'] = pretty_parse_vpc_name(vpcs_and_fw, "smart_groups")
        vpcs_and_fw = self.cleaner.remove_invalid_name_chars(vpcs_and_fw, "smart_groups")
        
        vpcs_and_fw['smart_groups'] = vpcs_and_fw['smart_groups'].apply(
            lambda x: self.create_smartgroup_reference(x)
        )
        
        vpcs_and_fw = vpcs_and_fw.groupby(['base_policy'])[
            'smart_groups'
        ].apply(list).reset_index()
        
        vpcs_and_fw['src_smart_groups'] = vpcs_and_fw['smart_groups']
        vpcs_and_fw['dst_smart_groups'] = vpcs_and_fw['smart_groups']
        vpcs_and_fw['action'] = vpcs_and_fw['base_policy'].map({
            "deny-all": 'DENY', 
            'allow-all': 'PERMIT', 
            'unknown': 'PERMIT'
        })
        
        vpcs_and_fw = vpcs_and_fw[['src_smart_groups', 'dst_smart_groups', 'base_policy', 'action']]
        
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
        catch_all_policies['web_groups'] = None
        catch_all_policies['port_ranges'] = None
        catch_all_policies['protocol'] = "ANY"
        catch_all_policies['logging'] = True
        catch_all_policies = catch_all_policies.reset_index(drop=True)
        
        # Add priorities (catch-all policies start at 3000)
        catch_all_policies.index = catch_all_policies.index + 3000
        catch_all_policies['priority'] = catch_all_policies.index
        
        if 'base_policy' in catch_all_policies.columns:
            catch_all_policies = catch_all_policies.drop('base_policy', axis=1)
        
        logging.info(f"Created {len(catch_all_policies)} catch-all policies")
        return catch_all_policies
    
    def _build_deny_policies(self, vpcs_and_fw: pd.DataFrame) -> List[pd.DataFrame]:
        """Build deny catch-all policies."""
        deny_pols = vpcs_and_fw[vpcs_and_fw['base_policy'] == 'deny-all']
        if len(deny_pols) == 0:
            return []
        
        deny_src_pols = deny_pols.copy()
        deny_src_pols['name'] = "CATCH_ALL_LEGACY_DENY_VPCS_SRC"
        deny_src_pols['dst_smart_groups'] = deny_src_pols['dst_smart_groups'].apply(lambda x: [self.anywhere_sg_id])
        
        deny_dst_pols = deny_pols.copy()
        deny_dst_pols['name'] = "CATCH_ALL_LEGACY_DENY_VPCS_DST"
        deny_dst_pols['src_smart_groups'] = deny_dst_pols['src_smart_groups'].apply(lambda x: [self.anywhere_sg_id])
        
        return [deny_src_pols, deny_dst_pols]
    
    def _build_allow_policies(self, vpcs_and_fw: pd.DataFrame) -> List[pd.DataFrame]:
        """Build allow catch-all policies."""
        allow_pols = vpcs_and_fw[vpcs_and_fw['base_policy'] == 'allow-all']
        if len(allow_pols) == 0:
            return []
        
        allow_src_pols = allow_pols.copy()
        allow_src_pols['name'] = "CATCH_ALL_LEGACY_ALLOW_VPCS_SRC"
        allow_src_pols['dst_smart_groups'] = allow_src_pols['dst_smart_groups'].apply(lambda x: [self.anywhere_sg_id])
        
        allow_dst_pols = allow_pols.copy()
        allow_dst_pols['name'] = "CATCH_ALL_LEGACY_ALLOW_VPCS_DST"
        allow_dst_pols['src_smart_groups'] = allow_dst_pols['src_smart_groups'].apply(lambda x: [self.anywhere_sg_id])
        
        return [allow_src_pols, allow_dst_pols]
    
    def _build_unknown_policies(self, vpcs_and_fw: pd.DataFrame) -> List[pd.DataFrame]:
        """Build unknown VPC catch-all policies."""
        unknown_pols = vpcs_and_fw[vpcs_and_fw['base_policy'] == 'unknown']
        if len(unknown_pols) == 0:
            return []
        
        unknown_src_pols = unknown_pols.copy()
        unknown_src_pols['name'] = "CATCH_ALL_LEGACY_UNKNOWN_VPCS_SRC"
        unknown_src_pols['dst_smart_groups'] = unknown_src_pols['dst_smart_groups'].apply(lambda x: [self.anywhere_sg_id])
        
        unknown_dst_pols = unknown_pols.copy()
        unknown_dst_pols['name'] = "CATCH_ALL_LEGACY_UNKNOWN_VPCS_DST"
        unknown_dst_pols['src_smart_groups'] = unknown_dst_pols['src_smart_groups'].apply(lambda x: [self.anywhere_sg_id])
        
        return [unknown_src_pols, unknown_dst_pols]
    
    def _build_global_catch_all(self) -> pd.DataFrame:
        """Build global catch-all policy."""
        return pd.DataFrame([{
            'src_smart_groups': [self.anywhere_sg_id],
            'dst_smart_groups': [self.anywhere_sg_id],
            'action': self.global_catch_all_action,
            'logging': False,
            'protocol': 'ANY',
            'name': 'GLOBAL_CATCH_ALL',
            'port_ranges': None,
            'web_groups': None
        }])


class HostnamePolicyBuilder(PolicyBuilder):
    """Builds policies using hostname SmartGroups for non-web FQDN traffic."""
    
    def __init__(self, internet_sg_id: str, anywhere_sg_id: str):
        super().__init__(internet_sg_id, anywhere_sg_id)
        self.cleaner = DataCleaner(TranslationConfig())
    
    def build_hostname_policies(self, gateways_df: pd.DataFrame, fqdn_df: pd.DataFrame,
                               hostname_smartgroups_df: pd.DataFrame, 
                               hostname_rules_df: pd.DataFrame) -> pd.DataFrame:
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
            (gateways_df['is_hagw'] == 'no') & 
            (gateways_df['enable_nat'] == 'yes')
        ].drop_duplicates(subset=['vpc_id', 'vpc_region', 'account_name'])
        
        if len(egress_vpcs) == 0:
            logging.info("No egress VPCs found")
            return pd.DataFrame()
        
        egress_vpcs = egress_vpcs[['fqdn_tags', 'vpc_name', 'vpc_id']]
        egress_vpcs['src_smart_groups'] = egress_vpcs['vpc_id']
        
        # Clean VPC names for SmartGroup references
        from ..data.processors import pretty_parse_vpc_name
        egress_vpcs['src_smart_groups'] = pretty_parse_vpc_name(egress_vpcs, "src_smart_groups")
        egress_vpcs = self.cleaner.remove_invalid_name_chars(egress_vpcs, "src_smart_groups")
        
        # Clean up disabled tag references
        disabled_tag_names = list(fqdn_df[fqdn_df['fqdn_enabled'] == False]['fqdn_tag'])
        egress_vpcs['fqdn_tags'] = egress_vpcs['fqdn_tags'].apply(
            lambda x: [item for item in x if item not in disabled_tag_names]
        )
        
        # Find VPCs that have FQDN tags that would map to hostname smartgroups
        egress_vpcs_with_hostname_tags = egress_vpcs.explode("fqdn_tags").rename(
            columns={'fqdn_tags': 'fqdn_tag'}
        )
        egress_vpcs_with_hostname_tags = egress_vpcs_with_hostname_tags.merge(
            fqdn_df, on="fqdn_tag", how='left'
        )
        egress_vpcs_with_hostname_tags = egress_vpcs_with_hostname_tags[
            egress_vpcs_with_hostname_tags['fqdn_enabled'] == True
        ]
        egress_vpcs_with_hostname_tags = egress_vpcs_with_hostname_tags.rename(
            columns={'fqdn_tag': 'fqdn_tag_name'}
        )
        
        # Match VPCs to hostname rules to determine which hostname smartgroups they should use
        vpc_hostname_matches = egress_vpcs_with_hostname_tags.merge(
            hostname_rules_df[['fqdn_tag_name', 'protocol', 'port', 'fqdn_mode', 'fqdn']],
            on=['fqdn_tag_name', 'fqdn_mode'],
            how='inner'
        )
        
        # Create policies for each VPC/hostname SmartGroup combination
        hostname_policies = []
        for _, sg_row in hostname_smartgroups_df.iterrows():
            protocol = sg_row['protocol']
            port = sg_row['port']
            fqdn_mode = sg_row['fqdn_mode']
            sg_name = sg_row['name']
            sg_fqdn_list = sg_row['fqdn_list']
            
            # Find VPCs that should use this hostname smartgroup
            matching_vpcs = vpc_hostname_matches[
                (vpc_hostname_matches['protocol'] == protocol) &
                (vpc_hostname_matches['port'] == port) &
                (vpc_hostname_matches['fqdn_mode'] == fqdn_mode) &
                (vpc_hostname_matches['fqdn'].isin(sg_fqdn_list))
            ].drop_duplicates(subset=['src_smart_groups'])
            
            if len(matching_vpcs) > 0:
                # Group by VPC to create one policy per VPC for this hostname smartgroup
                for vpc_name, vpc_group in matching_vpcs.groupby(['src_smart_groups', 'vpc_name']):
                    src_sg_name, vpc_display_name = vpc_name
                    src_sg_ref = self.create_smartgroup_reference(src_sg_name)
                    dst_sg_ref = self.create_smartgroup_reference(sg_name)
                    
                    action = 'PERMIT' if fqdn_mode == 'white' else 'DENY'
                    policy_name = f"FQDN_{vpc_display_name}_{'permit' if fqdn_mode == 'white' else 'deny'}"
                    
                    # Convert port to port_ranges format, handling special cases
                    if port == 'ALL':
                        port_ranges = None  # No port restrictions for ALL
                    else:
                        port_ranges = translate_port_to_port_range([port]) if port else None
                    
                    # Ensure protocol is properly formatted for DCF
                    dcf_protocol = protocol.upper()
                    if dcf_protocol == 'ALL':
                        dcf_protocol = 'ANY'
                    
                    hostname_policies.append({
                        'src_smart_groups': [src_sg_ref],
                        'dst_smart_groups': [dst_sg_ref],
                        'action': action,
                        'logging': True,
                        'protocol': dcf_protocol,
                        'name': policy_name,
                        'port_ranges': port_ranges,
                        'web_groups': None
                    })
        
        hostname_policies_df = pd.DataFrame(hostname_policies)
        if len(hostname_policies_df) > 0:
            hostname_policies_df = self.cleaner.remove_invalid_name_chars(hostname_policies_df, 'name')
            # Deduplicate policy names
            hostname_policies_df = self._deduplicate_policy_names(hostname_policies_df)
            # Add priorities - hostname policies get priority 1000+
            hostname_policies_df = hostname_policies_df.reset_index(drop=True)
            hostname_policies_df.index = hostname_policies_df.index + 1000
            hostname_policies_df['priority'] = hostname_policies_df.index
        
        logging.info(f"Created {len(hostname_policies_df)} hostname-based policies")
        return hostname_policies_df


class L4PolicyHandler:
    """Handler for L4 policy translation operations."""
    
    def __init__(self, config):
        """Initialize the L4 policy handler with configuration."""
        self.config = config
        self.policy_builder = L4PolicyBuilder(
            internet_sg_id=config.internet_sg_id,
            anywhere_sg_id=config.anywhere_sg_id
        )
    
    def build_l4_policies(self, fw_policy_df: pd.DataFrame) -> pd.DataFrame:
        """Build L4 DCF policies from legacy firewall policies."""
        return self.policy_builder.build_l4_policies(fw_policy_df)


# Legacy function wrappers for backward compatibility
def build_l4_dcf_policies(fw_policy_df: pd.DataFrame, internet_sg_id: str = "", 
                         anywhere_sg_id: str = "") -> pd.DataFrame:
    """Legacy wrapper for building L4 DCF policies."""
    builder = L4PolicyBuilder(internet_sg_id, anywhere_sg_id)
    return builder.build_l4_policies(fw_policy_df)


def build_internet_policies(gateways_df: pd.DataFrame, fqdn_df: pd.DataFrame,
                          webgroups_df: pd.DataFrame, any_webgroup_id: str,
                          internet_sg_id: str = "", anywhere_sg_id: str = "",
                          default_web_port_ranges: List[str] = None) -> pd.DataFrame:
    """Legacy wrapper for building internet policies."""
    if default_web_port_ranges is None:
        default_web_port_ranges = ["80", "443"]
    
    builder = InternetPolicyBuilder(internet_sg_id, anywhere_sg_id, 
                                  default_web_port_ranges, any_webgroup_id)
    return builder.build_internet_policies(gateways_df, fqdn_df, webgroups_df)


def build_catch_all_policies(gateways_df: pd.DataFrame, firewall_df: pd.DataFrame,
                           internet_sg_id: str = "", anywhere_sg_id: str = "",
                           global_catch_all_action: str = "PERMIT") -> pd.DataFrame:
    """Legacy wrapper for building catch-all policies."""
    builder = CatchAllPolicyBuilder(internet_sg_id, anywhere_sg_id, global_catch_all_action)
    return builder.build_catch_all_policies(gateways_df, firewall_df)


def build_hostname_policies(gateways_df: pd.DataFrame, fqdn_df: pd.DataFrame,
                          hostname_smartgroups_df: pd.DataFrame, hostname_rules_df: pd.DataFrame,
                          internet_sg_id: str = "", anywhere_sg_id: str = "") -> pd.DataFrame:
    """Legacy wrapper for building hostname policies."""
    builder = HostnamePolicyBuilder(internet_sg_id, anywhere_sg_id)
    return builder.build_hostname_policies(gateways_df, fqdn_df, 
                                         hostname_smartgroups_df, hostname_rules_df)
