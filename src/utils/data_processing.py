"""
Data processing utilities for the legacy-to-dcf-policy-translator.

This module contains utility functions for cleaning data, processing names,
translating ports, and handling policy deduplication.
"""

import logging
import ipaddress
import pandas as pd
import re
import tempfile
import os
from typing import List, Optional, Union

logger = logging.getLogger(__name__)


def remove_invalid_name_chars(df: pd.DataFrame, column: str) -> pd.DataFrame:
    """
    Remove invalid characters from names to ensure DCF compatibility.
    
    Cleans common invalid characters that can cause issues in DCF names:
    - Spaces, dots, slashes, colons become underscores or dashes
    - Special characters like ~, ?, *, etc. become underscores
    
    Args:
        df: DataFrame containing the column to clean
        column: Name of the column to process
        
    Returns:
        DataFrame with cleaned column values
    """
    # Create a copy to avoid modifying the original
    result_df = df.copy()
    
    # Convert to string first to handle mixed data types
    result_df[column] = result_df[column].astype(str)
    result_df[column] = result_df[column].str.strip()
    
    # Apply character replacements for DCF compatibility
    replacements = {
        '~': '_',
        ' ': '_',
        '/': '-',  # Use dash for path separators for readability
        '.': '_',
        ':': '_',   # Common in Azure strings
        '*': '_',
        '?': '_',
        '"': '_',
        '<': '_',
        '>': '_',
        '|': '_',
        '\t': '_',
        '\n': '_',
        '\r': '_',
        '@': '_',  # Email and special characters
        '#': '_',
        '$': '_',
        '%': '_',
        '&': '_',
        '(': '_',
        ')': '_',
        '+': '_',
        '=': '_',
        '[': '_',
        ']': '_',
        '{': '_',
        '}': '_',
        ';': '_',
        '!': '_'
    }
    
    for old_char, new_char in replacements.items():
        result_df[column] = result_df[column].str.replace(old_char, new_char, regex=False)
    
    return result_df


def pretty_parse_vpc_name(df: pd.DataFrame, column: str) -> pd.Series:
    """
    Clean VPC names for use in SmartGroup naming and selectors.
    
    Uses the full VPC ID and cleans invalid characters to create
    consistent, DCF-compatible names.
    
    Args:
        df: DataFrame containing VPC name/ID column
        column: Name of the column containing VPC names/IDs
        
    Returns:
        Series with cleaned VPC names
    """
    # Create a copy to avoid modifying the original
    temp_df = df.copy()
    
    # Use the full VPC ID and clean invalid characters
    temp_df = remove_invalid_name_chars(temp_df, column)
    
    return temp_df[column]


def translate_port_to_port_range(ports: List[Union[str, int]]) -> Optional[List[dict]]:
    """
    Convert port specifications to DCF port range format.
    
    Handles various port formats:
    - Single ports: '80' -> [{'lo': '80', 'hi': 0}]
    - Port ranges: '5022:5026' -> [{'lo': '5022', 'hi': '5026'}]
    - Empty/ALL ports: None (no port restrictions)
    
    Args:
        ports: List of port specifications (strings or integers)
        
    Returns:
        List of port range dictionaries in DCF format, or None for unrestricted
    """
    if not ports:
        return None
        
    ranges = []
    
    for port in ports:
        if port == '' or str(port).upper() == 'ALL':
            # Return None for empty or 'ALL' ports - no port restrictions
            return None
            
        # Convert to string and split on colon for ranges
        port_str = str(port)
        port_parts = port_str.split(':')
        
        if len(port_parts) == 2:
            # Port range format: "start:end"
            ranges.append({
                'lo': port_parts[0],
                'hi': port_parts[1]
            })
        else:
            # Single port format
            ranges.append({
                'lo': port_parts[0],
                'hi': 0
            })
    
    return ranges if ranges else None


def deduplicate_policy_names(policies_df: pd.DataFrame) -> pd.DataFrame:
    """
    Ensure policy names are unique by appending sequential numbers to duplicates.
    
    For example: policy_name, policy_name_2, policy_name_3, etc.
    
    Args:
        policies_df: DataFrame containing policies with 'name' column
        
    Returns:
        DataFrame with deduplicated policy names
    """
    if policies_df.empty or 'name' not in policies_df.columns:
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
    
    duplicates_fixed = sum(1 for count in name_counts.values() if count > 1)
    if duplicates_fixed > 0:
        logger.info(f"Fixed duplicate names for {duplicates_fixed} policy name groups")
    
    return df


def is_ipv4(string: str) -> bool:
    """
    Check if a string represents a valid IPv4 address or CIDR block.
    
    Args:
        string: String to check for IPv4 format
        
    Returns:
        True if string is a valid IPv4 address or CIDR, False otherwise
    """
    try:
        ipaddress.IPv4Network(string, strict=False)
        return True
    except ValueError:
        return False


def create_smartgroup_reference(sg_name: str) -> str:
    """
    Create a Terraform reference to a SmartGroup resource.
    
    Args:
        sg_name: Name of the SmartGroup
        
    Returns:
        Terraform reference string
    """
    return f"${{aviatrix_smart_group.{sg_name}.id}}"


def create_webgroup_reference(wg_name: str) -> str:
    """
    Create a Terraform reference to a WebGroup resource.
    
    Args:
        wg_name: Name of the WebGroup
        
    Returns:
        Terraform reference string
    """
    return f"${{aviatrix_web_group.{wg_name}.id}}"


def safe_list_to_string(value: Union[str, List[str]]) -> str:
    """
    Safely convert a value that might be a list or string to a string.
    
    Args:
        value: Value to convert (string or list)
        
    Returns:
        String representation
    """
    if isinstance(value, list):
        return ','.join(str(item) for item in value)
    return str(value)


def normalize_protocol(protocol: str) -> str:
    """
    Normalize protocol names for DCF compatibility.
    
    Args:
        protocol: Protocol name to normalize
        
    Returns:
        Normalized protocol name in uppercase
    """
    if not protocol or protocol.upper() in ['ALL', 'ANY']:
        return 'ANY'
    
    return protocol.upper()


def validate_dcf_name(name: str) -> bool:
    """
    Validate that a name meets DCF naming requirements.
    
    Args:
        name: Name to validate
        
    Returns:
        True if name is valid for DCF, False otherwise
    """
    if not name or len(name) == 0:
        return False
        
    # Check for invalid characters (this should match our replacement rules)
    invalid_chars = {'/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ', '\t', '\n', '\r', '~', '.'}
    
    return not any(char in name for char in invalid_chars)


def create_dcf_smartgroup_reference(sg_name: str) -> List[str]:
    """
    Create a DCF-compatible SmartGroup reference list.
    
    Args:
        sg_name: Name of the SmartGroup
        
    Returns:
        List containing the SmartGroup name for DCF policy format
    """
    return [sg_name]


def sanitize_terraform_file(file_path: str) -> str:
    """
    Sanitize Terraform file by removing AngularJS $$hashKey artifacts.
    
    Creates a temporary cleaned file that can be parsed by hcl2.
    
    Args:
        file_path: Path to the original Terraform file
        
    Returns:
        Path to the sanitized temporary file
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Remove $$hashKey lines (AngularJS artifacts)
        # Pattern matches: "$$hashKey" = "object:1795" or similar
        hashkey_pattern = r'\s*"?\$\$hashKey"?\s*=\s*"[^"]*"\s*\n?'
        cleaned_content = re.sub(hashkey_pattern, '', content)
        
        # Remove any trailing commas that might be left after removing hashKey lines
        # This handles cases where hashKey was the last item in a block
        cleaned_content = re.sub(r',(\s*})', r'\1', cleaned_content)
        
        # Create temporary file
        temp_fd, temp_path = tempfile.mkstemp(suffix='.tf', text=True)
        with os.fdopen(temp_fd, 'w', encoding='utf-8') as temp_file:
            temp_file.write(cleaned_content)
        
        return temp_path
        
    except Exception as e:
        logging.error(f"Error sanitizing Terraform file {file_path}: {e}")
        raise
