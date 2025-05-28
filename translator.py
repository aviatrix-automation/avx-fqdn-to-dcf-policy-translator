import hcl
import json
import logging
import os
import pandas as pd
import ipaddress
import argparse
import numpy as np


# TODO
# [x] Split fqdn tags webgroups into allow/deny
# [x] Render webroup policies as allow/deny with deny's first
# [] If an FQDN tag is applied, but has a source IP filter, this needs to be treated as a distinct entity from FQDN policies attached to the VPC.  Rather than using the source SmartGroup of the VPC, a dedicated Source SmartGroup should be created for the source IP filter.
# [] Add Webgroup policies in monitor mode for tags that are assigned but disabled
# [] Add additional port/proto combos for unsupported webgroups in `eval_unsupported_webgroups`
# [] Match logging policy for legacy L4
# [] Evaluate scenarios where an L4 stateful FW policy might be defined as relative to the VPC CIDR.  For example, a src 0.0.0.0/0 may need to be translated to the VPC CIDR due to it's relativity.

# config_path = "./test_files"
# output_path = "./output"
# debug_path = "./debug"

def ensure_directory_exists(path):
    """Ensure a directory exists, creating it if necessary."""
    if not os.path.exists(path):
        os.makedirs(path)

def get_arguments():
    parser = argparse.ArgumentParser(description="Your script description here")
    parser.add_argument('--loglevel', default="WARNING", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help="Set the logging level.")
    parser.add_argument('--internet-sg-id', default="def000ad-0000-0000-0000-000000000001", help="Internet security group ID.")
    parser.add_argument('--anywhere-sg-id', default="def000ad-0000-0000-0000-000000000000", help="Anywhere security group ID.")
    parser.add_argument('--any-webgroup-id', default="def000ad-0000-0000-0000-000000000002", help="Any webgroup ID.")
    parser.add_argument('--default-web-port-ranges', nargs='+', default=["80", "443"], help="Default web port ranges. Can provide multiple, space separated. Can provide a range by comma-delimiting.")
    parser.add_argument('--global-catch-all-action', default='PERMIT', choices=['PERMIT', 'DENY'], help="Global catch all action. Choices are 'PERMIT' or 'DENY'.")
    parser.add_argument('--config-path', default='./input', help="Path to the configuration files.")
    parser.add_argument('--output-path', default='./output', help="Path to save output files.")
    parser.add_argument('--debug-path', default='./debug', help="Path for debug files.")
    args = parser.parse_args()
    return args

# - [x] Alert on UDP or ANY protocol policies that have “force-drop” and no port defined.  This could cause bi-directional drops.
# - [x] Alert on UDP policies or ANY protocol policies that do not have a specific port defined.  These might create overly permissive rules in the new distributed cloud firewall


def eval_stateless_alerts(fw_policy_df):
    logging.info("Evaluating Stateless policy translation issues")
    stateless_alerts = fw_policy_df[((fw_policy_df['protocol'] == 'udp') | (fw_policy_df['protocol'] == 'all')) & (
        fw_policy_df['port'] == '') & ((fw_policy_df['action'] == 'allow') | (fw_policy_df['action'] == 'force-drop'))]
    if len(stateless_alerts) > 0:
        stateless_alerts.to_csv('{}/stateless_rule_issues.csv'.format(output_path))
    logging.info("Stateless Policy Issues: {}".format(len(stateless_alerts)))
    return stateless_alerts

# - [x] Filter out “inactive” FW tags that are disabled and/or not applied to any gateways


def eval_unused_fw_tags(fw_policy_df, fw_tag_df):
    logging.info("Evaluating unused firewall tags")
    unique_src_dst = pd.concat(
        [fw_policy_df['src_ip'], fw_policy_df['dst_ip']]).unique()
    unused_tags = set(fw_tag_df['firewall_tag']) - set(unique_src_dst)
    logging.info("Removing {}".format(unused_tags))
    fw_tag_df_new = fw_tag_df.drop(
        fw_tag_df[fw_tag_df['firewall_tag'].isin(unused_tags)].index)
    return fw_tag_df_new

# - [x] Check for equivalent CIDRs/Tags - for equivalent CIDRs/Tags, replace the reference in the rule with the tag


def eval_single_cidr_tag_match(fw_policy_df, fw_tag_df):
    logging.info("Evaluating Single CIDR firewall tags")
    single_cidr_tags = fw_tag_df[fw_tag_df['cidr_list'].apply(
        lambda x: isinstance(x, dict))].copy()
    single_cidr_tags['cidr'] = single_cidr_tags['cidr_list'].apply(
        lambda x: x['cidr'])
    single_cidr_tags = dict(
        zip(single_cidr_tags['cidr'], single_cidr_tags['firewall_tag']))
    logging.info("Count Single CIDR FW Tags before cleanup: {}. Attempting to replace them with matching named tags.".format(len(single_cidr_tags)))
    logging.debug(single_cidr_tags)
    fw_policy_df['src_ip'] = fw_policy_df['src_ip'].apply(
        lambda x: single_cidr_tags[x] if x in single_cidr_tags.keys() else x)
    fw_policy_df['dst_ip'] = fw_policy_df['dst_ip'].apply(
        lambda x: single_cidr_tags[x] if x in single_cidr_tags.keys() else x)
    return fw_policy_df

# - [x] Evaluate duplicate policies and export a CSV. Drop duplicates.


def remove_policy_duplicates(fw_policy_df):
    duplicates = fw_policy_df.duplicated(
        subset=['src_ip', 'dst_ip', 'protocol', 'port', 'action'])
    fw_policy_df.loc[duplicates].to_csv('{}/removed_duplicate_policies.csv'.format(output_path))
    return fw_policy_df.drop_duplicates(subset=['src_ip', 'dst_ip', 'protocol', 'port', 'action'])


# - [x] Create CIDR SmartGroups for each of the stateful firewall tags - named as the name of the tag
# - [x] Create CIDR SmartGroups for any directly referenced CIDRs in stateful firewall rules - named as the CIDR with special characters removed
# - [x] Create SmartGroups for all VPCs with selector matching VPC Name, Account, and Region - named as vpc_id
# Merge all created smartgroups and return an aggregate dataframe
def build_smartgroup_df(fw_policy_df, fw_tag_df, gateways_df):
    smartgroup_df = pd.DataFrame()
    sg_dfs = []
    # process fw tags
    if len(fw_tag_df)>0:
        fw_tag_df['selector'] = fw_tag_df['cidr_list'].apply(
            translate_fw_tag_to_sg_selector)
        fw_tag_df = fw_tag_df.rename(columns={'firewall_tag': 'name'})
        fw_tag_df = fw_tag_df[['name', 'selector']]
        sg_dfs.append(fw_tag_df)
    # process fw policy cidrs
    if len(fw_policy_df)>0:
        cidrs = pd.concat(
            [fw_policy_df['src_ip'], fw_policy_df['dst_ip']]).unique()
        cidrs = set(cidrs) - set(fw_tag_df['name'])
        cidr_sgs = []
        for cidr in cidrs:
            cidr_sgs.append(
                {'selector': {'match_expressions': {'cidr': cidr}}, 'name': "cidr_" + cidr})
        cidr_sg_df = pd.DataFrame(cidr_sgs)
        sg_dfs.append(cidr_sg_df)
    # process VPC SmartGroups
    vpcs = gateways_df.drop_duplicates(subset=['vpc_id', 'vpc_region', 'account_name']).copy()
   
    # Use the full vpc_id with invalid characters cleaned for both SmartGroup name and selector
    vpcs['vpc_name_attr'] = pretty_parse_vpc_name(vpcs, "vpc_id")

    vpcs['selector'] = vpcs.apply(lambda row: {'match_expressions': {"name": row['vpc_name_attr'],
                                                "region": row['vpc_region'],
                                                "account_name": row['account_name'],
                                                "type": "vpc"}}, axis=1)
    
    # Use the cleaned vpc_id as the SmartGroup name
    vpcs = vpcs.rename(columns={'vpc_name_attr': 'name'})
  
    # clean
    vpcs = vpcs[['name', 'selector']]
    sg_dfs.append(vpcs)
    # merge all smartgroup dataframes
    smartgroups = pd.concat(sg_dfs)
    # clean invalid characters
    smartgroups = remove_invalid_name_chars(smartgroups, 'name')
    return smartgroups


def remove_invalid_name_chars(df, column):
    # Convert to string first to handle mixed data types
    df[column] = df[column].astype(str)
    df[column] = df[column].str.strip()
    df[column] = df[column].str.replace('~', '_', regex=False)
    df[column] = df[column].str.replace(" ", "_", regex=False)
    df[column] = df[column].str.replace("/", "-", regex=False)
    df[column] = df[column].str.replace(".", "_", regex=False)
    #Commonly seen in Azure strings:
    df[column] = df[column].str.replace(":", "_", regex=False)
    return df

# Use full VPC ID with invalid characters removed for SmartGroup naming and selectors
def pretty_parse_vpc_name(df, column):
    # Create a copy of the dataframe to avoid modifying the original
    temp_df = df.copy()
    # Use the full VPC ID and clean invalid characters
    temp_df = remove_invalid_name_chars(temp_df, column)
    return temp_df[column]

# - [x] Create CIDR SmartGroups for each of the stateful firewall tags - named as the name of the tag
def translate_fw_tag_to_sg_selector(tag_cidrs):
    if isinstance(tag_cidrs, dict):
        match_expressions = {'cidr': tag_cidrs['cidr']}
    elif isinstance(tag_cidrs, list):
        match_expressions = []
        for cidr in tag_cidrs:
            match_expressions.append({'cidr': cidr['cidr']})
    else:
        match_expressions = None
    return {'match_expressions': match_expressions}


def eval_unsupported_webgroups(fqdn_tag_rule_df, fqdn_df):
    """
    Split FQDN rules into webgroup-supported and hostname smartgroup rules.
    All FQDN rules are now supported - no more truly unsupported rules.
    Returns tuple of (webgroup_rules, hostname_rules, truly_unsupported_rules)
    """
    fqdn_tag_rule_df = fqdn_tag_rule_df.merge(fqdn_df, left_on="fqdn_tag_name", right_on="fqdn_tag", how="left")
    
    # IMPORTANT: Only process enabled FQDN tags to maintain consistency with existing webgroup logic
    enabled_fqdn_rules = fqdn_tag_rule_df[fqdn_tag_rule_df['fqdn_enabled'] == True]
    
    # Define which ports are supported by webgroups (HTTP/HTTPS traffic)
    webgroup_supported_ports = set(default_web_port_ranges)
    
    # Rules that can use webgroups (HTTP/HTTPS on standard web ports)
    webgroup_rules = enabled_fqdn_rules[
        (enabled_fqdn_rules['protocol'].str.lower().isin(['tcp', 'http', 'https'])) &
        (enabled_fqdn_rules['port'].isin(webgroup_supported_ports))
    ]
    
    # ALL other enabled rules use hostname smartgroups (including protocol='all', SSH, blank ports)
    hostname_rules = enabled_fqdn_rules[
        ~((enabled_fqdn_rules['protocol'].str.lower().isin(['tcp', 'http', 'https'])) &
          (enabled_fqdn_rules['port'].isin(webgroup_supported_ports)))
    ]
    
    # Convert protocol "all" to "ANY" for DCF compatibility
    hostname_rules = hostname_rules.copy()
    hostname_rules.loc[hostname_rules['protocol'] == 'all', 'protocol'] = 'ANY'
    
    # Handle blank ports by setting to "ALL" for hostname SmartGroups
    hostname_rules.loc[hostname_rules['port'] == '', 'port'] = 'ALL'
    
    # No more truly unsupported rules - everything is handled
    unsupported_rules = pd.DataFrame()
    
    logging.info('FQDN rules split: {} webgroup rules, {} hostname rules, {} unsupported rules'.format(
        len(webgroup_rules), len(hostname_rules), len(unsupported_rules)))
    
    return webgroup_rules, hostname_rules, unsupported_rules


def build_webgroup_df(fqdn_tag_rule_df):
    fqdn_tag_rule_df = fqdn_tag_rule_df.groupby(['fqdn_tag_name', 'protocol', 'port', 'fqdn_mode'])[
        'fqdn'].apply(list).reset_index()
    fqdn_tag_rule_df['name'] = fqdn_tag_rule_df.apply(
        lambda row: "{}_{}_{}_{}".format(row['fqdn_tag_name'], row['fqdn_mode'], row['protocol'], row['port']), axis=1)
    fqdn_tag_rule_df['selector'] = fqdn_tag_rule_df['fqdn'].apply(
        translate_fqdn_tag_to_sg_selector)
    # Note: Using Aviatrix built-in "Any" webgroup instead of creating custom any-domain webgroup
    fqdn_tag_rule_df = remove_invalid_name_chars(fqdn_tag_rule_df , "name")
    return fqdn_tag_rule_df


def translate_fqdn_tag_to_sg_selector(fqdn_list):
    match_expressions = []
    for fqdn in fqdn_list:
        match_expressions.append({'snifilter': fqdn.strip()})
    return {'match_expressions': match_expressions}


def is_ipv4(string):
    try:
        ipaddress.IPv4Network(string)
        return True
    except ValueError:
        return False


def translate_port_to_port_range(ports):
    ranges = []
    for port in ports:
        if port == '' or str(port).upper() == 'ALL':
            # Return None for empty or 'ALL' ports - no port restrictions
            return None
        port = str(port).split(':')
        if len(port) == 2:
            ranges.append([{
                'lo': port[0],
                'hi':port[1]
            }])
        else:
            ranges.append([{
                'lo': port[0],
                'hi':0
            }])
    return ranges if ranges else None


def build_l4_dcf_policies(fw_policy_df):
    # consolidate policies to have multiple ports
    fw_policy_df = fw_policy_df.groupby(['src_ip', 'dst_ip', 'protocol', 'action', 'log_enabled'])[
        'port'].apply(list).reset_index()
    fw_policy_df['port_ranges'] = fw_policy_df['port'].apply(
        translate_port_to_port_range)
    # Update fw_policy_df source and dst to match smartgroup naming
    # Prepend cidr_ to values that are a cidr
    for column in ['src_ip', 'dst_ip']:
        fw_policy_df[column] = fw_policy_df[column].apply(
            lambda x: 'cidr_' + x if is_ipv4(x) else x)
        fw_policy_df = remove_invalid_name_chars(fw_policy_df, column)
    # create new column with sg tf reference format
    fw_policy_df['src_smart_groups'] = fw_policy_df['src_ip'].apply(
        lambda x: ['${{aviatrix_smart_group.{}.id}}'.format(x)])
    fw_policy_df['dst_smart_groups'] = fw_policy_df['dst_ip'].apply(
        lambda x: ['${{aviatrix_smart_group.{}.id}}'.format(x)])
    fw_policy_df['action'] = fw_policy_df['action'].apply(
        lambda x: 'PERMIT' if x == 'allow' else 'DENY')
    fw_policy_df['logging'] = fw_policy_df['log_enabled'].apply(
        lambda x: False if x == 'FALSE' else True)
    fw_policy_df['protocol'] = fw_policy_df['protocol'].str.upper()
    fw_policy_df.loc[fw_policy_df['protocol'] == '', 'protocol'] = 'ANY'
    fw_policy_df['protocol'] = fw_policy_df['protocol'].str.replace(
        'ALL', 'ANY')
    fw_policy_df['name'] = fw_policy_df.apply(lambda row: "{}_{}".format(
        row['src_ip'], row['dst_ip']), axis=1)
    fw_policy_df = fw_policy_df[['src_smart_groups', 'dst_smart_groups',
                                 'action', 'logging', 'protocol', 'name', 'port_ranges']]
    # Deduplicate policy names
    fw_policy_df = deduplicate_policy_names(fw_policy_df)
    # create rule priorities
    fw_policy_df = fw_policy_df.reset_index(drop=True)
    fw_policy_df.index = fw_policy_df.index + 100
    fw_policy_df['priority'] = fw_policy_df.index
    return fw_policy_df


def build_internet_policies(gateways_df, fqdn_df, webgroups_df, any_webgroup_id):
    egress_vpcs = gateways_df[(gateways_df['is_hagw'] == 'no') & (
        gateways_df['enable_nat'] == 'yes')].drop_duplicates(subset=['vpc_id', 'vpc_region', 'account_name'])
    egress_vpcs = egress_vpcs[[
        'fqdn_tags', 'stateful_fw', 'egress_control', 'vpc_name', 'vpc_id']]
    egress_vpcs['src_smart_groups'] = egress_vpcs['vpc_id']

    #Ensure we have a clean smart group name.
    egress_vpcs['src_smart_groups'] = pretty_parse_vpc_name(egress_vpcs, "src_smart_groups")
 
    egress_vpcs = remove_invalid_name_chars(egress_vpcs, "src_smart_groups")

    egress_vpcs['src_smart_groups'] = egress_vpcs['src_smart_groups'].apply(
        lambda x: '${{aviatrix_smart_group.{}.id}}'.format(x))
    # Clean up disabled tag references - identify disabled tag names
    disabled_tag_names = list(
        fqdn_df[fqdn_df['fqdn_enabled'] == False]['fqdn_tag'])
    # Find and alert on VPCs that contain disabled tags. Disabled tags will not be included in the new policy
    egress_vpcs_with_disabled_tags = egress_vpcs[egress_vpcs['fqdn_tags'].apply(
        lambda x: any(item in disabled_tag_names for item in x))]
    logging.warning("{} VPCs have disabled FQDN tags.  Policies for these tags will be ignored.".format(len(egress_vpcs_with_disabled_tags)))
    logging.warning(egress_vpcs_with_disabled_tags)
    # Remove disabled tags from the dataframe
    egress_vpcs['fqdn_tags'] = egress_vpcs['fqdn_tags'].apply(
        lambda x: [item for item in x if item not in disabled_tag_names])
    
    # Build individual policies for egress VPCs that have an "Enabled" FQDN tag applied.  May create multiple policies per VPC divided by unique port/protocol/action tag
    egress_vpcs_with_enabled_tags = egress_vpcs.explode("fqdn_tags").rename(columns={'fqdn_tags': 'fqdn_tag'}).merge(fqdn_df, on="fqdn_tag",how='left')
    egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags[egress_vpcs_with_enabled_tags['fqdn_enabled']==True]
    egress_vpcs_with_enabled_tags = egress_vpcs_with_enabled_tags.rename(columns={'fqdn_tag': 'fqdn_tag_name'})
    fqdn_tag_policies = egress_vpcs_with_enabled_tags.merge(webgroups_df, on=['fqdn_tag_name', 'fqdn_mode'], how='left')
    fqdn_tag_policies['web_groups'] = fqdn_tag_policies['name'].apply(
        lambda x: '${{aviatrix_web_group.{}.id}}'.format(x))
    fqdn_tag_policies = fqdn_tag_policies.groupby(['src_smart_groups','vpc_name', 'protocol', 'port','fqdn_mode'])[
        'web_groups'].apply(list).reset_index()
    fqdn_tag_policies['src_smart_groups']=fqdn_tag_policies['src_smart_groups'].apply(lambda x: [x])
    fqdn_tag_policies['dst_smart_groups']=internet_sg_id
    fqdn_tag_policies['dst_smart_groups']=fqdn_tag_policies['dst_smart_groups'].apply(lambda x: [x])
    fqdn_tag_policies['action']=fqdn_tag_policies['fqdn_mode'].apply(
        lambda x: 'PERMIT' if x == 'white' else 'DENY')
    fqdn_tag_policies['port_ranges']=fqdn_tag_policies['port'].apply(lambda x: [x]).apply(translate_port_to_port_range)
    fqdn_tag_policies['logging']=True
    fqdn_tag_policies['protocol']=fqdn_tag_policies['protocol'].str.upper()
    fqdn_tag_policies['name'] = fqdn_tag_policies.apply(
        lambda row: "Egress_{}_{}".format(row['vpc_name'], row['fqdn_mode']), axis=1)
    fqdn_tag_policies = fqdn_tag_policies[['src_smart_groups','dst_smart_groups','action','port_ranges','logging','protocol','name','web_groups']]

    # Build default policies for fqdn tags based on default action - whitelist/blacklist - create a single policy for all whitelist tags, and all blacklist tags
    fqdn_tag_default_policies = egress_vpcs_with_enabled_tags.groupby(['fqdn_mode'])['src_smart_groups'].apply(list).reset_index()
    fqdn_tag_default_policies['dst_smart_groups']=internet_sg_id
    fqdn_tag_default_policies['dst_smart_groups']=fqdn_tag_default_policies['dst_smart_groups'].apply(lambda x: [x])
    fqdn_tag_default_policies['logging']=True
    fqdn_tag_default_policies['protocol']="ANY"
    fqdn_tag_default_policies['port_ranges']=None
    fqdn_tag_default_policies['web_groups']=None
    fqdn_tag_default_policies['action']=fqdn_tag_default_policies['fqdn_mode'].apply(
        lambda x: 'DENY' if x == 'white' else 'PERMIT')
    fqdn_tag_default_policies['name'] = fqdn_tag_default_policies['fqdn_mode'].apply(
        lambda x: 'Egress-AllowList-Default' if x == 'white' else 'Egress-DenyList-Default')
    fqdn_tag_default_policies = fqdn_tag_default_policies.drop(columns='fqdn_mode')

    # Build policy for egress VPCs that only have NAT and no fqdn tags.  This renders as a single policy.  Src VPCs, Dst Internet, Port/Protocol Any.
    egress_vpcs_with_nat_only = egress_vpcs[(
        egress_vpcs['fqdn_tags'].astype(str) == '[]')]

    nat_only_policies = pd.DataFrame([{'src_smart_groups': list(egress_vpcs_with_nat_only['src_smart_groups']), 'dst_smart_groups':[internet_sg_id],
                                       'action':'PERMIT', 'logging':True, 'protocol':'ANY', 'name':'Egress-Allow-All', 'port_ranges':None, 'web_groups': None}])
    # Build policy for egress VPCs that have discovery enabled.  This renders as 2 policies.  One policy with the "any" webgroup for port 80 and 443.  Another policy below for "any" protocol without a webgroup.
    egress_vpcs_with_discovery = egress_vpcs[(
        egress_vpcs['fqdn_tags'].astype(str).str.contains('-discovery'))]
    
    #If Discovery is disabled, this is unnecessary:
    if not egress_vpcs_with_discovery.empty:
        discovery_policies_l7 = pd.DataFrame([{'src_smart_groups': list(egress_vpcs_with_discovery['src_smart_groups']), 'dst_smart_groups':[internet_sg_id],
                                            'action':'PERMIT', 'logging':True, 'protocol':'TCP', 'name':'Egress-Discovery-L7', 'port_ranges':translate_port_to_port_range(default_web_port_ranges), 'web_groups': [any_webgroup_id]}])
        
        discovery_policies_l4 = pd.DataFrame([{'src_smart_groups': list(egress_vpcs_with_discovery['src_smart_groups']), 'dst_smart_groups':[internet_sg_id],
                                            'action':'PERMIT', 'logging':True, 'protocol':'ANY', 'name':'Egress-Discovery-L4', 'port_ranges':None, 'web_groups': None}])
    else:
        discovery_policies_l4 = pd.DataFrame()
        discovery_policies_l7 = pd.DataFrame()    



    # Merge policies together, skipping any empty data frames.
    internet_egress_policies = pd.DataFrame()
    for data_frame in [fqdn_tag_policies,fqdn_tag_default_policies,discovery_policies_l7,discovery_policies_l4,nat_only_policies]:

        #if list(data_frame["src_smart_groups"]) == [[]]:
        #    continue

        internet_egress_policies = pd.concat([internet_egress_policies, data_frame])

    #internet_egress_policies = pd.concat([fqdn_tag_policies,fqdn_tag_default_policies,discovery_policies_l7,discovery_policies_l4,nat_only_policies])
    
    #Merge policies together, omitting the l4,l7 discovery items
    #internet_egress_policies = pd.concat([fqdn_tag_policies,fqdn_tag_default_policies,nat_only_policies])
    
    internet_egress_policies = internet_egress_policies.reset_index(drop=True)
    
    # Sort policies with proper ordering:
    # - Black mode: DENY specific webgroups first, then ALLOW default
    # - White mode: ALLOW specific webgroups first, then DENY default
    def get_policy_priority(row):
        web_groups = row['web_groups']
        # Check if web_groups is None, NaN, empty list, or contains None values
        if web_groups is None:
            is_default_policy = True
        elif isinstance(web_groups, list):
            # Check if list is empty or contains only None values
            is_default_policy = len(web_groups) == 0 or all(x is None for x in web_groups)
        else:
            # Handle scalar values that might be NaN
            try:
                is_default_policy = pd.isna(web_groups)
            except (ValueError, TypeError):
                is_default_policy = False
            
        if is_default_policy:
            return 2  # Default policies come after specific policies
        else:
            return 1  # Specific webgroup policies come first
    
    internet_egress_policies['sort_priority'] = internet_egress_policies.apply(get_policy_priority, axis=1)
    internet_egress_policies = internet_egress_policies.sort_values(['sort_priority']).drop(columns=['sort_priority'])
    internet_egress_policies = internet_egress_policies.reset_index(drop=True)
    
    # Deduplicate policy names
    internet_egress_policies = deduplicate_policy_names(internet_egress_policies)
    
    internet_egress_policies.index = internet_egress_policies.index + 2000  # Webgroup/internet policies start at 2000
    internet_egress_policies['priority'] = internet_egress_policies.index
    return internet_egress_policies

# Build default policies.  VPCs with a default L4 policy will maintain the L4 base.  VPCs without any L4 policy will have an allow-all

def build_catch_all_policies(gateways_df,firewall_df):
    # Remove HAGWs
    gateways_df = gateways_df[gateways_df['is_hagw']=="no"]
    # Enrich gateway details with FW default policy
    if len(firewall_df)>0:
        vpcs_and_fw = gateways_df.merge(firewall_df, left_on="vpc_name", right_on="gw_name", how="left")
    else:
        vpcs_and_fw = gateways_df.copy()
        vpcs_and_fw['base_policy'] = np.nan
    # Sort by VPCs with known policies, then remove duplicate VPCs (could be caused by having spokes and standalones or multiple standalones)
    vpcs_and_fw = vpcs_and_fw.sort_values(['base_policy']).drop_duplicates(subset = ['vpc_id'],keep='first')
    # Fill blank base policies with unknown for further processing
    vpcs_and_fw['base_policy']=vpcs_and_fw['base_policy'].fillna('unknown')
    # Prep Smartgroup column naming
    vpcs_and_fw['smart_groups']=vpcs_and_fw['vpc_id']

    #Ensure we have a clean smart group name.
    vpcs_and_fw['smart_groups'] = pretty_parse_vpc_name(vpcs_and_fw, "smart_groups")
    vpcs_and_fw = remove_invalid_name_chars(vpcs_and_fw, "smart_groups") #MG - FOCUS HERE



    vpcs_and_fw['smart_groups'] = vpcs_and_fw['smart_groups'].apply(
        lambda x: '${{aviatrix_smart_group.{}.id}}'.format(x))
    vpcs_and_fw = vpcs_and_fw.groupby(['base_policy'])[
        'smart_groups'].apply(list).reset_index()
    vpcs_and_fw['src_smart_groups']= vpcs_and_fw['smart_groups']
    vpcs_and_fw['dst_smart_groups']= vpcs_and_fw['smart_groups']
    vpcs_and_fw['action']=vpcs_and_fw['base_policy'].map({"deny-all": 'DENY', 'allow-all': 'PERMIT', 'unknown': 'PERMIT'})
    vpcs_and_fw = vpcs_and_fw[['src_smart_groups','dst_smart_groups','base_policy','action']]

    # Create Deny rules
    deny_pols = vpcs_and_fw[vpcs_and_fw['base_policy']=='deny-all']
    deny_src_pols = deny_pols.copy()
    deny_dst_pols = deny_pols.copy()
    if len(deny_pols)>0:
        deny_src_pols['name'] = "CATCH_ALL_LEGACY_DENY_VPCS_SRC"
        deny_src_pols['dst_smart_groups'] = anywhere_sg_id
        deny_src_pols['dst_smart_groups']=deny_src_pols['dst_smart_groups'].apply(lambda x: [x])
        deny_dst_pols['name'] = "CATCH_ALL_LEGACY_DENY_VPCS_DST"
        deny_dst_pols['src_smart_groups'] = anywhere_sg_id
        deny_dst_pols['src_smart_groups']=deny_dst_pols['src_smart_groups'].apply(lambda x: [x])
    
    # Create Allow rules
    allow_pols = vpcs_and_fw[vpcs_and_fw['base_policy']=='allow-all']
    allow_src_pols = allow_pols.copy()
    allow_dst_pols = allow_pols.copy()
    if len(allow_pols) > 0:
        allow_src_pols['name'] = "CATCH_ALL_LEGACY_ALLOW_VPCS_SRC"
        allow_src_pols['dst_smart_groups'] = anywhere_sg_id
        allow_src_pols['dst_smart_groups']=allow_src_pols['dst_smart_groups'].apply(lambda x: [x])
        allow_dst_pols['name'] = "CATCH_ALL_LEGACY_ALLOW_VPCS_DST"
        allow_dst_pols['src_smart_groups'] = anywhere_sg_id
        allow_dst_pols['src_smart_groups']=allow_dst_pols['src_smart_groups'].apply(lambda x: [x])
    
    # Create Unknown Rules (VPCs that didn't have an explicit Stateful FW default action)
    unknown_pols = vpcs_and_fw[vpcs_and_fw['base_policy']=='unknown']
    unknown_src_pols = unknown_pols.copy()

    unknown_dst_pols = unknown_pols.copy()
    if len(unknown_pols) > 0:
        unknown_src_pols['name'] = "CATCH_ALL_LEGACY_UNKNOWN_VPCS_SRC"
        unknown_src_pols['dst_smart_groups'] = anywhere_sg_id
        unknown_src_pols['dst_smart_groups']=unknown_src_pols['dst_smart_groups'].apply(lambda x: [x])
        unknown_dst_pols['name'] = "CATCH_ALL_LEGACY_UNKNOWN_VPCS_DST"
        unknown_dst_pols['src_smart_groups'] = anywhere_sg_id
        unknown_dst_pols['src_smart_groups']=unknown_dst_pols['src_smart_groups'].apply(lambda x: [x])

    
    # Create Global Catch All
    global_catch_all = pd.DataFrame([{'src_smart_groups': [anywhere_sg_id], 'dst_smart_groups':[anywhere_sg_id],
                                       'action':global_catch_all_action, 'logging':False, 'protocol':'ANY', 'name':'GLOBAL_CATCH_ALL', 'port_ranges':None, 'web_groups': None}])

    catch_all_policies = pd.concat([deny_src_pols,deny_dst_pols,allow_src_pols,allow_dst_pols,unknown_src_pols,unknown_dst_pols,global_catch_all])
    # catch_all_policies = pd.concat([deny_src_pols,deny_dst_pols,allow_src_pols,allow_dst_pols])
    catch_all_policies['web_groups']= None
    catch_all_policies['port_ranges']= None
    catch_all_policies['protocol']= "ANY"
    catch_all_policies['logging']= True
    catch_all_policies = catch_all_policies.reset_index(drop=True)
    catch_all_policies.index = catch_all_policies.index + 3000  # Catch-all policies start at 3000
    catch_all_policies['priority'] = catch_all_policies.index
    catch_all_policies = catch_all_policies.drop('base_policy', axis=1)
    return catch_all_policies

# - [x] Export TF json: SmartGroups, Webgroups, Rules

def export_dataframe_to_tf(df, resource_name, name_column):
    tf_resource_dict = df.to_dict(orient='records')
    tf_resource_dict = [{x[name_column]:x} for x in tf_resource_dict]
    tf_resource_dict = {'resource': {resource_name: tf_resource_dict}}
    with open('{}/{}.tf.json'.format(output_path, resource_name), 'w') as json_file:
        json.dump(tf_resource_dict, json_file, indent=1)


def create_dataframe(tf_resource, resource_name):
    tf_resource_df = pd.DataFrame([tf_resource[x] for x in tf_resource.keys()])
    if LOGLEVEL == "DEBUG":
        tf_resource_df.to_csv('{}/{}.csv'.format(debug_path, resource_name))
    return tf_resource_df


def load_tf_resource(resource_name):
    with open('{}/{}.tf'.format(config_path, resource_name), 'r') as fp:
        resource_dict = hcl.load(fp)
        if "resource" in resource_dict.keys():
            resource_dict = resource_dict["resource"]['aviatrix_{}'.format(
                resource_name)]
        else:
            resource_dict = {}
        resource_df = create_dataframe(resource_dict, resource_name)
        logging.info("Number of {}: {}".format(
            resource_name, len(resource_df)))
        logging.debug(resource_df.head())
    return resource_df



def ensure_dir_exists(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def build_hostname_smartgroups(hostname_rules_df):
    """
    Build hostname SmartGroups for FQDN rules that don't use webgroups.
    Groups FQDNs by protocol/port combination for optimization.
    """
    if len(hostname_rules_df) == 0:
        return pd.DataFrame(columns=['name', 'selector'])
    
    # Group FQDNs by protocol, port, and fqdn_mode for optimization
    grouped = hostname_rules_df.groupby(['protocol', 'port', 'fqdn_mode'])['fqdn'].apply(list).reset_index()
    
    hostname_smartgroups = []
    for _, row in grouped.iterrows():
        # Create a unique name for the hostname smartgroup
        protocol = row['protocol'].lower()
        port = str(row['port']).lower()  # Handle ALL and other special port values
        mode = row['fqdn_mode']
        
        # Create a hash for uniqueness when there are many FQDNs
        fqdn_list = row['fqdn']
        fqdn_hash = abs(hash(str(sorted(fqdn_list)))) % 10000
        
        name = f"fqdn_{protocol}_{port}_{mode}_{fqdn_hash}"
        
        # Create selector for hostname smartgroup using fqdn field
        if len(fqdn_list) == 1:
            selector = {'match_expressions': {'fqdn': fqdn_list[0].strip()}}
        else:
            # For multiple FQDNs, create multiple match expressions
            match_expressions = []
            for fqdn in fqdn_list:
                match_expressions.append({'fqdn': fqdn.strip()})
            selector = {'match_expressions': match_expressions}
        
        hostname_smartgroups.append({
            'name': name,
            'selector': selector,
            'protocol': row['protocol'],  # Store original protocol value (ANY, etc.)
            'port': row['port'],         # Store original port value (ALL, etc.)
            'fqdn_mode': mode,
            'fqdn_list': fqdn_list
        })
    
    hostname_sg_df = pd.DataFrame(hostname_smartgroups)
    hostname_sg_df = remove_invalid_name_chars(hostname_sg_df, 'name')
    
    logging.info(f"Created {len(hostname_sg_df)} hostname SmartGroups")
    return hostname_sg_df


def deduplicate_policy_names(policies_df):
    """
    Deduplicate policy names by appending sequential numbers to duplicates.
    For example: policy_name, policy_name_2, policy_name_3, etc.
    """
    if policies_df.empty:
        return policies_df
    
    # Create a copy to avoid modifying the original
    df = policies_df.copy()
    
    # Track name counts
    name_counts = {}
    
    # Process each policy name
    for idx in df.index:
        original_name = df.at[idx, 'name']
        
        if original_name in name_counts:
            # This is a duplicate - increment counter and append number
            name_counts[original_name] += 1
            new_name = f"{original_name}_{name_counts[original_name]}"
            df.at[idx, 'name'] = new_name
        else:
            # First occurrence of this name
            name_counts[original_name] = 1
    
    return df


def build_hostname_policies(gateways_df, fqdn_df, hostname_smartgroups_df, hostname_rules_df):
    """
    Build L4 policies using hostname SmartGroups as destinations.
    Creates one policy per unique (src VPC, protocol/port, hostname SmartGroup) combination.
    """
    if len(hostname_smartgroups_df) == 0 or len(hostname_rules_df) == 0:
        return pd.DataFrame()
    
    # Get egress VPCs (same logic as in build_internet_policies)
    egress_vpcs = gateways_df[(gateways_df['is_hagw'] == 'no') & (
        gateways_df['enable_nat'] == 'yes')].drop_duplicates(subset=['vpc_id', 'vpc_region', 'account_name'])
    
    if len(egress_vpcs) == 0:
        return pd.DataFrame()
    
    egress_vpcs = egress_vpcs[['fqdn_tags', 'vpc_name', 'vpc_id']]
    egress_vpcs['src_smart_groups'] = egress_vpcs['vpc_id']
    
    # Clean VPC names for SmartGroup references
    egress_vpcs['src_smart_groups'] = pretty_parse_vpc_name(egress_vpcs, "src_smart_groups")
    egress_vpcs = remove_invalid_name_chars(egress_vpcs, "src_smart_groups")
    
    # Clean up disabled tag references
    disabled_tag_names = list(fqdn_df[fqdn_df['fqdn_enabled'] == False]['fqdn_tag'])
    egress_vpcs['fqdn_tags'] = egress_vpcs['fqdn_tags'].apply(
        lambda x: [item for item in x if item not in disabled_tag_names])
    
    # Find VPCs that have FQDN tags that would map to hostname smartgroups
    egress_vpcs_with_hostname_tags = egress_vpcs.explode("fqdn_tags").rename(columns={'fqdn_tags': 'fqdn_tag'})
    egress_vpcs_with_hostname_tags = egress_vpcs_with_hostname_tags.merge(fqdn_df, on="fqdn_tag", how='left')
    egress_vpcs_with_hostname_tags = egress_vpcs_with_hostname_tags[egress_vpcs_with_hostname_tags['fqdn_enabled']==True]
    egress_vpcs_with_hostname_tags = egress_vpcs_with_hostname_tags.rename(columns={'fqdn_tag': 'fqdn_tag_name'})
    
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
        # Match by protocol, port, fqdn_mode and overlapping FQDNs
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
                src_sg_ref = f"${{aviatrix_smart_group.{src_sg_name}.id}}"
                dst_sg_ref = f"${{aviatrix_smart_group.{sg_name}.id}}"
                
                action = 'PERMIT' if fqdn_mode == 'white' else 'DENY'
                policy_name = f"FQDN_{vpc_display_name}_{fqdn_mode}"
                
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
        hostname_policies_df = remove_invalid_name_chars(hostname_policies_df, 'name')
        # Deduplicate policy names
        hostname_policies_df = deduplicate_policy_names(hostname_policies_df)
        # Add priorities - hostname policies get priority 1000+
        hostname_policies_df = hostname_policies_df.reset_index(drop=True)
        hostname_policies_df.index = hostname_policies_df.index + 1000  # Hostname policies start at 1000
        hostname_policies_df['priority'] = hostname_policies_df.index
    
    logging.info(f"Created {len(hostname_policies_df)} hostname-based policies")
    return hostname_policies_df


def main():
    # Fetch arguments
    args = get_arguments()
    global LOGLEVEL
    LOGLEVEL = args.loglevel
    logging.basicConfig(level=args.loglevel)
    global internet_sg_id
    internet_sg_id = args.internet_sg_id
    global anywhere_sg_id
    anywhere_sg_id = args.anywhere_sg_id
    global any_webgroup_id
    any_webgroup_id = args.any_webgroup_id
    # could add range delimited by : eg. 80:81
    global default_web_port_ranges
    default_web_port_ranges = args.default_web_port_ranges
    global global_catch_all_action
    global_catch_all_action = args.global_catch_all_action
    global config_path
    config_path = args.config_path
    global output_path
    output_path = args.output_path
    global debug_path
    debug_path = args.debug_path

    # Ensure output and debug directories exist
    ensure_directory_exists(output_path)
    ensure_directory_exists(debug_path)

    # Load TF exports
    fw_tag_df = load_tf_resource('firewall_tag')
    fw_policy_df = load_tf_resource('firewall_policy')
    fw_gw_df = load_tf_resource('firewall')
    fqdn_tag_rule_df = load_tf_resource('fqdn_tag_rule')
    fqdn_df = load_tf_resource('fqdn')

    # Load VPC/Gateway Configuration
    with open('{}/gateway_details.json'.format(config_path), 'r') as fp:
        gateway_details = json.load(fp)
        gateways_df = pd.DataFrame(gateway_details['results'])
        if LOGLEVEL == "DEBUG":
            gateways_df.to_csv('{}/gateway_details.csv'.format(debug_path))
        # logging.info(gateways_df)

    # Evaluate and clean existing L4 policies.  Generate warnings for unsupported policies.
    if len(fw_policy_df)>0:
        stateless_alerts = eval_stateless_alerts(fw_policy_df)
        fw_tag_df = eval_unused_fw_tags(fw_policy_df, fw_tag_df)
        fw_policy_df = eval_single_cidr_tag_match(fw_policy_df, fw_tag_df)
        fw_policy_df = remove_policy_duplicates(fw_policy_df)
        if LOGLEVEL == "DEBUG":
            fw_policy_df.to_csv('{}/clean_policies.csv'.format(debug_path))

    # Create Smartgroups
    smartgroups_df = build_smartgroup_df(fw_policy_df, fw_tag_df, gateways_df)
    export_dataframe_to_tf(smartgroups_df, 'aviatrix_smart_group', 'name')

    # Create L4 policies (not including catch-all)
    if len(fw_policy_df)>0:
        l4_dcf_policies_df = build_l4_dcf_policies(fw_policy_df)
        l4_dcf_policies_df['web_groups'] = None
        l4_policies_dict = l4_dcf_policies_df.to_dict(orient='records')
        l4_policies_dict = {'resource': {'aviatrix_distributed_firewalling_policy_list': {
            'distributed_firewalling_policy_list_1': {'policies': l4_policies_dict}}}}
        with open('{}/aviatrix_distributed_firewalling_policy_list.tf.json'.format(output_path), 'w') as json_file:
            json.dump(l4_policies_dict, json_file, indent=1)

    # Split FQDN rules into webgroup and hostname smartgroup categories FIRST
    # This prioritizes hostname smartgroups over webgroups for processing efficiency
    webgroup_rules_df, hostname_rules_df, unsupported_rules_df = eval_unsupported_webgroups(fqdn_tag_rule_df, fqdn_df)
    
    # Create Hostname SmartGroups first (higher priority processing)
    hostname_smartgroups_df = build_hostname_smartgroups(hostname_rules_df)
    
    # Create Webgroups for remaining web traffic (HTTP/HTTPS on standard ports)
    if LOGLEVEL == "DEBUG":
        webgroup_rules_df.to_csv('{}/clean_fqdn_webgroups.csv'.format(debug_path))
        hostname_rules_df.to_csv('{}/clean_fqdn_hostnames.csv'.format(debug_path))
    
    webgroups_df = build_webgroup_df(webgroup_rules_df)
    export_dataframe_to_tf(webgroups_df[['name','selector']], 'aviatrix_web_group', 'name')
    
    # Merge hostname SmartGroups with existing SmartGroups
    if len(hostname_smartgroups_df) > 0:
        # Add hostname SmartGroups to the existing smartgroups
        hostname_sg_for_export = hostname_smartgroups_df[['name', 'selector']].copy()
        smartgroups_df = pd.concat([smartgroups_df, hostname_sg_for_export], ignore_index=True)
        # Re-export the updated SmartGroups including hostname ones
        export_dataframe_to_tf(smartgroups_df, 'aviatrix_smart_group', 'name')
    
    # Export final SmartGroups to CSV (including FQDN SmartGroups if any were created)
    smartgroups_df.to_csv('{}/smartgroups.csv'.format(output_path))

    # Create Hostname policies for non-web FQDN traffic (processed before Internet policies)
    hostname_policies_df = build_hostname_policies(gateways_df, fqdn_df, hostname_smartgroups_df, hostname_rules_df)

    # Create Internet policies (for remaining webgroup traffic)
    internet_rules_df = build_internet_policies(gateways_df, fqdn_df, webgroups_df, any_webgroup_id)

    # Create Default Policies
    catch_all_rules_df = build_catch_all_policies(gateways_df, fw_gw_df)

    # Merge all policies and create final policy list (hostname policies first for efficiency)
    policy_dataframes = []
    if len(fw_policy_df) > 0:
        policy_dataframes.append(l4_dcf_policies_df)
    if len(hostname_policies_df) > 0:
        policy_dataframes.append(hostname_policies_df)
    policy_dataframes.append(internet_rules_df)  # Internet/webgroup policies after hostname policies
    policy_dataframes.append(catch_all_rules_df)
    
    full_policy_list = pd.concat(policy_dataframes, ignore_index=True)
    
    # Final deduplication across all policy types
    full_policy_list = deduplicate_policy_names(full_policy_list)
    
    full_policy_list.to_csv('{}/full_policy_list.csv'.format(output_path))
    full_policy_list['exclude_sg_orchestration'] = True
    full_policy_dict = full_policy_list.to_dict(orient='records')
    full_policy_dict = {'resource': {'aviatrix_distributed_firewalling_policy_list': {
        'distributed_firewalling_policy_list_1': {'policies': full_policy_dict}}}}
    with open('{}/aviatrix_distributed_firewalling_policy_list.tf.json'.format(output_path), 'w') as json_file:
        json.dump(full_policy_dict, json_file, indent=1)

    ## Create main.tf
    main_tf = '''terraform {
  required_providers {
    aviatrix = {
      source  = "AviatrixSystems/aviatrix"
      version = ">=8.0"
    }
  }
}

provider "aviatrix" {
  skip_version_validation = true
}'''

    with open('{}/main.tf'.format(output_path), 'w') as f:
        f.write(main_tf)

    # Show final policy counts
    hostname_sg_count = len(hostname_smartgroups_df) if len(hostname_smartgroups_df) > 0 else 0
    hostname_policy_count = len(hostname_policies_df) if len(hostname_policies_df) > 0 else 0
    
    logging.info("Number of SmartGroups: {} (including {} hostname SmartGroups)".format(len(smartgroups_df), hostname_sg_count))
    logging.info("Number of WebGroups: {}".format(len(webgroups_df)))
    logging.info("Number of Hostname Policies: {}".format(hostname_policy_count))
    logging.info("Number of Distributed Cloud Firewall Policies: {}".format(len(full_policy_list)))

LOGLEVEL = ""
internet_sg_id = ""
anywhere_sg_id = ""
default_web_port_ranges = ""
global_catch_all_action = ""
config_path = ""
output_path = ""
debug_path = ""

if __name__ == '__main__':
    main()

