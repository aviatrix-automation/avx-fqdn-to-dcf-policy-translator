import hcl
import json
import logging
import os
import pandas as pd
import ipaddress
import argparse
import numpy as np


# TODO
# [] Split fqdn tags webgroups into allow/deny
# [] Render webroup policies as allow/deny with deny's first
# [] Add Webgroup policies in monitor mode for tags that are assigned but disabled
# [] Add additional port/proto combos for unsupported webgroups in `eval_unsupported_webgroups`
# [] Match logging policy for legacy L4
# [] Evaluate scenarios where an L4 stateful FW policy might be defined as relative to the VPC CIDR.  For example, a src 0.0.0.0/0 may need to be translated to the VPC CIDR due to it's relativity.

# LOGLEVEL = 'WARNING'
# logging.basicConfig(level=LOGLEVEL)
# internet_sg_id = "def000ad-0000-0000-0000-000000000001"
# anywhere_sg_id = "def000ad-0000-0000-0000-000000000000"
# any_webgroup_id = "def000ad-0000-0000-0000-000000000002"
# # could add range delimited by : eg. 80:81
# default_web_port_ranges = ["80", "443"]
# global_catch_all_action = "PERMIT"

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
   
    #Ensure we have a clean smart group name.
    vpcs['vpc_name_attr']  = pretty_parse_vpc_name(vpcs, "vpc_id")

    vpcs['selector'] = vpcs.apply(lambda row: {'match_expressions': {"name": row['vpc_name_attr'],
                                                "region": row['vpc_region'],
                                                "account_name": row['account_name'],
                                                "type": "vpc"}}, axis=1)
    
    #Make the smart group name prettier
    vpcs = vpcs.rename(columns={'vpc_name_attr': 'name'})
  
    # clean
    vpcs = vpcs[['name', 'selector']]
    sg_dfs.append(vpcs)
    # merge all smartgroup dataframes
    smartgroups = pd.concat(sg_dfs)
    # clean invalid characters
    smartgroups = remove_invalid_name_chars(smartgroups, 'name')
    smartgroups.to_csv('{}/smartgroups.csv'.format(output_path))
    return smartgroups


def remove_invalid_name_chars(df, column):
    df[column] = df[column].str.strip()
    df[column] = df[column].str.replace('~', '_', regex=False)
    df[column] = df[column].str.replace(" ", "_", regex=False)
    df[column] = df[column].str.replace("/", "-", regex=False)
    df[column] = df[column].str.replace(".", "_", regex=False)
    #Commonly seen in Azure strings:
    df[column] = df[column].str.replace(":", "_", regex=False)
    return df

# Delimit VPC name based on CSP format (~~ for AWS, ~-~ for GCP, : for Azure)
def pretty_parse_vpc_name(df, column):
    return np.where(
        df[column].str.contains('~~'),
        df[column].str.split('~~').str[1],
        np.where(
            df[column].str.contains('~-~'),
            df[column].str.split('~-~').str[0],
            np.where(
                df[column].str.contains(':'),
                df[column].str.split(':').str[0],
                df[column]
            )
        )
    )

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


def eval_unsupported_webgroups(fqdn_tag_rule_df,fqdn_df):
    fqdn_tag_rule_df = fqdn_tag_rule_df.merge(fqdn_df, left_on="fqdn_tag_name", right_on="fqdn_tag", how="left")
    unsupported_rules = fqdn_tag_rule_df[(
        fqdn_tag_rule_df['protocol'] == 'all') | (fqdn_tag_rule_df['port'] == '22')]
    if len(unsupported_rules) > 0:
        unsupported_rules.to_csv('{}/unsupported_fqdn_rules.csv'.format(output_path))
        logging.warning('{} rules are unsupported by webgroups and will need to be manually addressed.'.format(
            len(unsupported_rules)))
        logging.warning(unsupported_rules)
    fqdn_tag_rule_df = fqdn_tag_rule_df[~(
        (fqdn_tag_rule_df['protocol'] == 'all') | (fqdn_tag_rule_df['port'] == '22'))]
    return fqdn_tag_rule_df


def build_webgroup_df(fqdn_tag_rule_df):
    fqdn_tag_rule_df = fqdn_tag_rule_df.groupby(['fqdn_tag_name', 'protocol', 'port'])[
        'fqdn'].apply(list).reset_index()
    fqdn_tag_rule_df['name'] = fqdn_tag_rule_df.apply(
        lambda row: "{}_{}_{}".format(row['fqdn_tag_name'], row['protocol'], row['port']), axis=1)
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
        if port == '':
            break
        port = port.split(':')
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
    return ranges


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
    fqdn_tag_policies = egress_vpcs_with_enabled_tags.merge(webgroups_df, on='fqdn_tag_name', how='left')
    fqdn_tag_policies['web_groups'] = fqdn_tag_policies['name'].apply(
        lambda x: '${{aviatrix_web_group.{}.id}}'.format(x))
    fqdn_tag_policies = fqdn_tag_policies.groupby(['src_smart_groups','vpc_name', 'protocol', 'port','fqdn_mode'])[
        'web_groups'].apply(list).reset_index()
    fqdn_tag_policies['src_smart_groups']=fqdn_tag_policies['src_smart_groups'].apply(lambda x: [x])
    fqdn_tag_policies['dst_smart_groups']=internet_sg_id
    fqdn_tag_policies['dst_smart_groups']=fqdn_tag_policies['dst_smart_groups'].apply(lambda x: [x])
    fqdn_tag_policies['action']="PERMIT"
    fqdn_tag_policies['port_ranges']=fqdn_tag_policies['port'].apply(lambda x: [x]).apply(translate_port_to_port_range)
    fqdn_tag_policies['logging']=True
    fqdn_tag_policies['protocol']=fqdn_tag_policies['protocol'].str.upper()
    fqdn_tag_policies['name'] = fqdn_tag_policies['vpc_name'].apply(lambda x: "Egress_{}".format(x))
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
        lambda x: 'DENY' if x == 'white' else 'ALLOW')
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
    internet_egress_policies.index = internet_egress_policies.index + 1000
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
        deny_src_pols['name'] = "CATCH_ALL_LEGACY_DENY_VPCS"
        deny_src_pols['dst_smart_groups'] = anywhere_sg_id
        deny_src_pols['dst_smart_groups']=deny_src_pols['dst_smart_groups'].apply(lambda x: [x])
        deny_dst_pols['name'] = "CATCH_ALL_LEGACY_DENY_VPCS"
        deny_dst_pols['src_smart_groups'] = anywhere_sg_id
        deny_dst_pols['src_smart_groups']=deny_dst_pols['src_smart_groups'].apply(lambda x: [x])
    
    # Create Allow rules
    allow_pols = vpcs_and_fw[vpcs_and_fw['base_policy']=='allow-all']
    allow_src_pols = allow_pols.copy()
    allow_dst_pols = allow_pols.copy()
    if len(allow_pols) > 0:
        allow_src_pols['name'] = "CATCH_ALL_LEGACY_ALLOW_VPCS"
        allow_src_pols['dst_smart_groups'] = anywhere_sg_id
        allow_src_pols['dst_smart_groups']=allow_src_pols['dst_smart_groups'].apply(lambda x: [x])
        allow_dst_pols['name'] = "CATCH_ALL_LEGACY_ALLOW_VPCS"
        allow_dst_pols['src_smart_groups'] = anywhere_sg_id
        allow_dst_pols['src_smart_groups']=allow_dst_pols['src_smart_groups'].apply(lambda x: [x])
    
    # Create Unknown Rules (VPCs that didn't have an explicit Stateful FW default action)
    unknown_pols = vpcs_and_fw[vpcs_and_fw['base_policy']=='unknown']
    unknown_src_pols = unknown_pols.copy()

    unknown_dst_pols = unknown_pols.copy()
    if len(unknown_pols) > 0:
        unknown_src_pols['name'] = "CATCH_ALL_LEGACY_UNKNOWN_VPCS"
        unknown_src_pols['dst_smart_groups'] = anywhere_sg_id
        unknown_src_pols['dst_smart_groups']=unknown_src_pols['dst_smart_groups'].apply(lambda x: [x])
        unknown_dst_pols['name'] = "CATCH_ALL_LEGACY_UNKNOWN_VPCS"
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
    catch_all_policies.index = catch_all_policies.index + 2000
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
        tf_resource_df.to_csv('{}/{}.csv'.format(resource_name,debug_path))
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


def main():
    # Fetch arguments
    args = get_arguments()
    global LOGLEVEL
    loglevel=args.loglevel
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

    # Create Webgroups
    fqdn_tag_rule_df = eval_unsupported_webgroups(fqdn_tag_rule_df,fqdn_df)
    if LOGLEVEL == "DEBUG":
        fqdn_tag_rule_df.to_csv('{}/clean_fqdn.csv'.format(debug_path))
    webgroups_df = build_webgroup_df(fqdn_tag_rule_df)
    export_dataframe_to_tf(webgroups_df[['name','selector']], 'aviatrix_web_group', 'name')

    # Create Internet policies
    internet_rules_df = build_internet_policies(gateways_df, fqdn_df, webgroups_df, any_webgroup_id)

    # Create Default Policies
    catch_all_rules_df = build_catch_all_policies(gateways_df, fw_gw_df)

    # Merge all policies and create final policy list
    if len(fw_policy_df)>0:
        full_policy_list = pd.concat([l4_dcf_policies_df, internet_rules_df,catch_all_rules_df])
    else:
        full_policy_list = pd.concat([internet_rules_df,catch_all_rules_df])
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
      version = ">=3.1"
    }
  }
}

provider "aviatrix" {
  skip_version_validation = true
}'''
    with open('{}/main.tf'.format(output_path), 'w') as f:
        f.write(main_tf)

    # Show final policy counts
    logging.info("Number of SmartGroups: {}".format(len(smartgroups_df)))
    logging.info("Number of WebGroups: {}".format(len(webgroups_df)))
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

