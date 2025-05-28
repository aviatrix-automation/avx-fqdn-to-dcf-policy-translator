#!/usr/bin/env python3
"""
Legacy Policy Bundle Exporter for Aviatrix Controller

This script exports legacy stateful firewall and FQDN egress policies from an Aviatrix 
controller to prepare for migration to Distributed Cloud Firewall (DCF). It connects to 
the controller via API and downloads Terraform configuration files for various resource 
types that are then bundled into a ZIP file.

This is the first step in the migration process from legacy stateful firewall and FQDN 
egress filtering to Distributed Cloud Firewall. The exported bundle is later processed 
by the translator.py script to convert legacy policies into DCF-compatible configuration.

For more information, see the README.md file.

Author: Aviatrix Systems
"""

import argparse
import getpass
import requests
import json
import zipfile
import io
import os
from tqdm import tqdm

# Disable SSL warnings for API calls to Aviatrix controller
requests.packages.urllib3.disable_warnings()


def get_arguments():
    """
    Parse command line arguments for the legacy policy export script.
    
    This function sets up the argument parser with all required and optional parameters
    for connecting to the Aviatrix controller and configuring the export process.
    
    Returns:
        argparse.Namespace: Parsed command line arguments containing:
            - controller_ip: IP address of the Aviatrix controller
            - username: Username for controller authentication
            - password: Password for controller authentication (prompted if not provided)
            - output: Output ZIP file name (default: 'legacy_policy_bundle.zip')
            - any_web: Flag to download Any-Web webgroup ID (requires v7.1+)
            - vpc_routes: Flag to include VPC route table details
            - cid: Manually provided CID to skip login
    """
    # Creates argument parser object
    parser = argparse.ArgumentParser(
        description='Collects Controller IP, username, and password.')
    parser.add_argument('-i', '--controller_ip',
                        help='Controller IP address', required=True)
    parser.add_argument('-u', '--username', help='Username', required=False)
    parser.add_argument('-p', '--password', help='Password', required=False)
    parser.add_argument('-o', '--output', help='Output file name',
                        default='legacy_policy_bundle.zip')
    parser.add_argument(
        '-w', '--any_web', help='Download the Any Webgroup ID. Controller version must be v7.1 or greater', action='store_true')
    parser.add_argument('-r', '--vpc_routes', help='Get route table details for VPCs. Used in translator to add rules for peering connections and VPN gateways if migrating those elements to AVX transit.', action='store_true')
    parser.add_argument('-c', '--cid', help='Manually provide CID.', default=None)

    args = parser.parse_args()

    # If password isn't provided as an argument, prompt for it securely (no echo)
    if args.password is None:
        args.password = getpass.getpass('Password: ')

    return args


def login(controller_ip, controller_user, controller_password):
    """
    Authenticate with the Aviatrix controller and obtain a session CID.
    
    This function performs authentication against the Aviatrix controller API
    and returns a CID (session token) that is used for subsequent API calls.
    
    Args:
        controller_ip (str): IP address or hostname of the Aviatrix controller
        controller_user (str): Username for authentication
        controller_password (str): Password for authentication
        
    Returns:
        str: CID (session token) for authenticated API calls
        
    Raises:
        requests.exceptions.HTTPError: If HTTP request fails
        requests.exceptions.ConnectionError: If connection to controller fails
        requests.exceptions.Timeout: If request times out
        requests.exceptions.RequestException: For other request-related errors
    """
    # Format the URL for the controller API
    url = "https://{}/v2/api".format(controller_ip)

    # Define payload for authentication
    payload = {'action': 'login',
               'username': controller_user,
               'password': controller_password}

    headers = {}

    try:
        # Make a POST request to authenticate with the controller
        response = requests.post(url, headers=headers,
                                 data=payload, verify=False)

        # Check if response status is not 200 (HTTP OK), and if so, raise an error
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        print("Http Error:", errh)
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        print("Oops: Something Else", err)
    
    # Return the CID (session token) from the response for subsequent API calls
    return response.json()["CID"]


def aviatrix_api_call(controller_ip, path, cid, params={}, stream=False):
    """
    Make an authenticated API call to the Aviatrix controller.
    
    This function handles both v2 and v2.5 API endpoints, automatically adding
    the appropriate authentication method (CID parameter for v2, Authorization
    header for v2.5).
    
    Args:
        controller_ip (str): IP address or hostname of the Aviatrix controller
        path (str): API endpoint path (e.g., "/v2/api" or "/v2.5/api/app-domains")
        cid (str): Session token from login
        params (dict, optional): Additional parameters for the API call
        stream (bool, optional): Whether to stream the response (for large downloads)
        
    Returns:
        requests.Response: The HTTP response object
        
    Raises:
        requests.exceptions.HTTPError: If HTTP request fails
        requests.exceptions.ConnectionError: If connection to controller fails
        requests.exceptions.Timeout: If request times out
        requests.exceptions.RequestException: For other request-related errors
    """
    # print(cid)
    try:
        # Handle different API versions with appropriate authentication methods
        if "/v2.5/" in path:
            # v2.5 API uses Authorization header
            headers = {"Authorization": "cid {}".format(cid)}
            response = requests.get("https://{}{}".format(controller_ip, path),
                                    params=params, headers=headers, verify=False)
        else:
            # v2 API uses CID as a parameter
            params['CID'] = cid
            response = requests.get("https://{}{}".format(controller_ip, path),
                                    params=params, stream=stream, verify=False)

        # Check if response status is not 200 (HTTP OK), and if so, raise an error
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        print("Http Error:", errh)
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        print("Oops: Something Else", err)
    return response


def get_gateway_details(controller_ip, cid):
    """
    Retrieve gateway and VPC details from the Aviatrix controller.
    
    This function fetches comprehensive information about all gateways and VPCs
    managed by the controller, which is used by the translator for creating
    appropriate SmartGroups and understanding the network topology.
    
    Args:
        controller_ip (str): IP address or hostname of the Aviatrix controller
        cid (str): Session token from login
        
    Returns:
        dict: JSON response containing gateway and VPC details
    """
    print("Getting gateway details.")
    response = aviatrix_api_call(controller_ip=controller_ip, path="/v2/api",
                                 cid=cid, params={'action': 'list_vpcs_summary'})
    return response.json()


def get_vpc_routes(controller_ip, cid, gateway_details):
    """
    Collect VPC route table information for all gateways.
    
    This function iterates through all gateways and collects their route table
    information. This data is used by the translator to add rules for peering
    connections and VPN gateways when migrating to Aviatrix transit architecture.
    
    Args:
        controller_ip (str): IP address or hostname of the Aviatrix controller
        cid (str): Session token from login
        gateway_details (dict): Gateway details from get_gateway_details()
        
    Returns:
        dict: Mapping of VPC IDs to their route table information
    """
    print("Getting VPC Route tables.")
    # Parse gateway details to create a mapping of VPC ID to gateway name
    vpcs = {}
    for gateway in gateway_details['results']:
        vpcs[gateway['vpc_id']] = gateway['gw_name']
    
    # Collect route tables for each VPC
    vpc_routes = {}
    pbar = tqdm(vpcs.keys())
    for vpc in pbar:
        pbar.set_description("Getting routes tables for {}".format(vpc))
        response = aviatrix_api_call(controller_ip=controller_ip, path="/v2/api",
                                     cid=cid, params={'action': 'get_transit_or_spoke_gateway_details','option':'vpc_route','gateway_name':vpcs[vpc]})
        vpc_routes[vpc] = response.json()['results']
    return vpc_routes


def get_any_webgroup_id(controller_ip, cid):
    """
    Retrieve the "Any-Web" webgroup ID from the controller.
    
    The Any-Web webgroup is a built-in webgroup available in controller v7.1+
    that represents all web traffic. This ID is required by the translator
    script and is unique per controller installation.
    
    Args:
        controller_ip (str): IP address or hostname of the Aviatrix controller
        cid (str): Session token from login
        
    Returns:
        list: List containing the Any-Web webgroup information
        
    Note:
        Requires controller version 7.1 or greater
    """
    print("Getting Any-Web webgroup.")
    response = aviatrix_api_call(controller_ip, "/v2.5/api/app-domains", cid)
    # Filter the app domains to find the "Any-Web" webgroup
    webgroup = [x for x in response.json()['app_domains']
                if x['name'] == "Any-Web"]
    return webgroup


def get_tf_resources(controller_ip, resource, cid):
    """
    Download Terraform resource configuration files from the controller.
    
    This function exports Terraform configuration for specific resource types
    from the Aviatrix controller. The exported files contain the current
    configuration of legacy firewall policies and FQDN rules that will be
    translated to DCF format.
    
    Args:
        controller_ip (str): IP address or hostname of the Aviatrix controller
        resource (str): Type of Terraform resource to export (e.g., 'firewall', 'fqdn')
        cid (str): Session token from login
        
    Note:
        The function downloads a ZIP file and extracts the .tf file to the current directory.
        If extraction fails, an error message is printed but execution continues.
        
    Resource types typically include:
        - firewall: Stateful firewall rules
        - firewall_policy: Firewall policy assignments
        - firewall_tag: Firewall tags (groups of CIDRs)
        - fqdn: FQDN filtering rules
        - fqdn_pass_through: FQDN pass-through rules
        - fqdn_tag_rule: FQDN tag rule assignments
    """
    print("Getting {} TF resource config.".format(resource))
    response = aviatrix_api_call(
        controller_ip, "/v2/api?action=export_terraform_resource", cid, params={"resource": resource}, stream=True)
    try:
        # Extract the Terraform file from the downloaded ZIP
        z = zipfile.ZipFile(io.BytesIO(response.content))
        z.extract("{}.tf".format(resource))
    except:
        print("Could not extract TF resource {}".format(resource))


def main():
    """
    Main function that orchestrates the legacy policy export process.
    
    This function:
    1. Parses command line arguments
    2. Authenticates with the Aviatrix controller (or uses provided CID)
    3. Exports gateway details and optionally VPC routes and Any-Web webgroup
    4. Downloads Terraform configurations for all legacy firewall resources
    5. Bundles everything into a ZIP file for use with the translator
    
    The exported bundle contains all necessary information for the translator.py
    script to convert legacy policies to Distributed Cloud Firewall format.
    
    For detailed usage information, see README.md or run with --help flag.
    """
    # Fetch arguments
    args = get_arguments()

    # Use provided arguments to login and get CID, or use manually provided CID
    if args.cid == None:
        cid = login(args.controller_ip, args.username, args.password)
    else:
        cid = args.cid

    # Get gateway details using the CID - this provides VPC and gateway information
    gateway_details = get_gateway_details(args.controller_ip, cid)

    # Optionally get VPC route tables if requested
    # This is useful for migration scenarios involving transit gateways
    if args.vpc_routes == True:
        vpc_route_tables = get_vpc_routes(
            args.controller_ip, cid, gateway_details)
        with open('vpc_route_tables.json', 'w') as f:
            json.dump(vpc_route_tables, f, indent=1)

    # Write the gateway details to the output file as JSON
    with open('gateway_details.json', 'w') as f:
        json.dump(gateway_details, f, indent=1)

    # Optionally get the ID of the "Any-Web" webgroup (requires controller v7.1+)
    # This is required for the translator script
    if args.any_web == True:
        any_webgroup = get_any_webgroup_id(args.controller_ip, cid)
        # Write the Any-Web webgroup details to JSON file
        with open('any_webgroup.json', 'w') as f:
            json.dump(any_webgroup, f, indent=1)

    # Download Terraform configurations for all required legacy firewall resources
    # These resources contain the current policy configuration that will be translated
    resources = ["firewall", "firewall_policy", "firewall_tag",
                 "fqdn", "fqdn_pass_through", "fqdn_tag_rule"]
    for resource in resources:
        get_tf_resources(args.controller_ip, resource, cid)

    # Bundle all the files into a ZIP and delete the original files to clean up
    # Determine which additional files to include based on command line options
    other_files = ["gateway_details.json"]
    if args.any_web == True:
        other_files = other_files + ["any_webgroup.json"]
    if args.vpc_routes == True:
        other_files = other_files + ["vpc_route_tables.json"]
    
    # Create the complete file list for the ZIP bundle
    files = ["{}.tf".format(x) for x in resources] + other_files
    
    # Create the ZIP file with all exported data
    zf = zipfile.ZipFile(args.output, mode="w")
    try:
        for file_name in files:
            # Add each file to the zip bundle
            # Parameters: source file, name in zip, compression type
            zf.write(file_name, file_name, compress_type=zipfile.ZIP_STORED)
            # Clean up the individual file after adding to ZIP
            os.remove(file_name)

    except FileNotFoundError:
        print("An error occurred - some expected files were not found")
    finally:
        # Ensure the ZIP file is properly closed
        zf.close()
        print(f"Legacy policy bundle exported to: {args.output}")


if __name__ == '__main__':
    """
    Entry point for the script when run directly.
    
    This script should be run against an Aviatrix controller to export
    legacy firewall and FQDN policies in preparation for migration to
    Distributed Cloud Firewall.
    
    Example usage:
        python3 export_legacy_policy_bundle.py -i 10.0.0.1 -u admin -w -r
        
    For complete usage information, see README.md or run with --help
    """
    main()
