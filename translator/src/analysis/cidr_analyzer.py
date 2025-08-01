"""
CIDR Analysis Module for Custom Internet SmartGroup Detection

This module provides functionality to analyze VPC CIDR ranges and determine
if custom Internet SmartGroups are required for non-RFC1918/CGNAT networks.
"""

import ipaddress
import logging
from typing import List, Set, Tuple

import pandas as pd


class CIDRAnalyzer:
    """Analyzes CIDR ranges to determine custom Internet SmartGroup requirements."""

    # RFC1918 Private Address Ranges
    RFC1918_RANGES = [
        ipaddress.IPv4Network("192.168.0.0/16"),  # Class C private
        ipaddress.IPv4Network("10.0.0.0/8"),      # Class A private
        ipaddress.IPv4Network("172.16.0.0/12"),   # Class B private
    ]

    # CGNAT (Carrier-Grade NAT) Range - RFC6598
    CGNAT_RANGES = [
        ipaddress.IPv4Network("100.64.0.0/10"),   # Shared Address Space
    ]

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Combine all standard private ranges
        self.standard_private_ranges = self.RFC1918_RANGES + self.CGNAT_RANGES

    def is_rfc1918_or_cgnat(self, cidr_str: str) -> bool:
        """
        Check if a CIDR is within standard private ranges (RFC1918 or CGNAT).
        
        Args:
            cidr_str: CIDR string (e.g., "192.168.1.0/24")
            
        Returns:
            True if CIDR is within RFC1918 or CGNAT ranges, False otherwise
        """
        try:
            cidr_network = ipaddress.IPv4Network(cidr_str, strict=False)
            
            # Check if the CIDR overlaps with any standard private range
            for private_range in self.standard_private_ranges:
                if (cidr_network.subnet_of(private_range) or 
                    cidr_network.supernet_of(private_range) or
                    cidr_network.overlaps(private_range)):
                    return True
                    
            return False
            
        except (ipaddress.AddressValueError, ValueError) as e:
            self.logger.warning(f"Invalid CIDR format: {cidr_str} - {e}")
            return False

    def extract_vpc_cidrs_from_gateway_data(self, gateways_df: pd.DataFrame) -> List[str]:
        """
        Extract all VPC CIDR ranges from gateway details DataFrame.
        
        Args:
            gateways_df: DataFrame containing gateway configuration data
            
        Returns:
            List of unique CIDR strings found in VPC configurations
        """
        vpc_cidrs = []
        
        if gateways_df.empty:
            self.logger.info("No gateway data provided for CIDR extraction")
            return vpc_cidrs

        # Extract CIDRs from vpc_cidr column
        if 'vpc_cidr' in gateways_df.columns:
            for _, row in gateways_df.iterrows():
                vpc_cidr_value = row.get('vpc_cidr')
                if vpc_cidr_value is not None and not (isinstance(vpc_cidr_value, (list, tuple)) and len(vpc_cidr_value) == 0):
                    if not (pd.isna(vpc_cidr_value) if not isinstance(vpc_cidr_value, (list, tuple)) else False):
                        cidrs = self._parse_cidr_field(vpc_cidr_value)
                        vpc_cidrs.extend(cidrs)

        # Extract CIDRs from customized_cidr_list column
        if 'customized_cidr_list' in gateways_df.columns:
            for _, row in gateways_df.iterrows():
                customized_cidr_value = row.get('customized_cidr_list')
                if customized_cidr_value is not None and not (isinstance(customized_cidr_value, (list, tuple)) and len(customized_cidr_value) == 0):
                    if not (pd.isna(customized_cidr_value) if not isinstance(customized_cidr_value, (list, tuple)) else False):
                        cidrs = self._parse_cidr_field(customized_cidr_value)
                        vpc_cidrs.extend(cidrs)

        # Remove duplicates and return
        unique_cidrs = list(set(vpc_cidrs))
        self.logger.info(f"Extracted {len(unique_cidrs)} unique VPC CIDRs from gateway data")
        
        if unique_cidrs:
            self.logger.debug(f"VPC CIDRs found: {unique_cidrs}")
            
        return unique_cidrs

    def _parse_cidr_field(self, cidr_field) -> List[str]:
        """
        Parse CIDR field which may contain various formats:
        - String representation of list: "['10.0.0.0/16', '11.0.0.0/16']"
        - JSON array string: "[\"10.0.0.0/16\"]"
        - Single CIDR string: "10.0.0.0/16"
        - Empty array or None
        """
        cidrs = []
        
        # Handle None or empty cases
        if cidr_field is None:
            return cidrs
            
        # Handle empty arrays/lists
        if isinstance(cidr_field, (list, tuple)):
            if len(cidr_field) == 0:
                return cidrs
            # Already a list, validate each item
            for cidr in cidr_field:
                if isinstance(cidr, str) and cidr.strip() and self._is_valid_cidr_format(cidr):
                    cidrs.append(cidr)
            return cidrs
        
        if isinstance(cidr_field, str):
            # Handle empty string
            if not cidr_field.strip():
                return cidrs
                
            # Remove common formatting characters
            cleaned = cidr_field.strip().strip("[]").replace("'", "").replace('"', '')
            
            # Handle empty cleaned string
            if not cleaned.strip():
                return cidrs
            
            # Split by comma if multiple CIDRs
            if ',' in cleaned:
                potential_cidrs = [c.strip() for c in cleaned.split(',')]
            else:
                potential_cidrs = [cleaned.strip()]
                
            # Validate each potential CIDR
            for cidr in potential_cidrs:
                if cidr and self._is_valid_cidr_format(cidr):
                    cidrs.append(cidr)
                    
        return cidrs

    def _is_valid_cidr_format(self, cidr_str: str) -> bool:
        """Basic validation of CIDR format."""
        try:
            ipaddress.IPv4Network(cidr_str, strict=False)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    def requires_custom_internet_smartgroup(self, vpc_cidrs: List[str]) -> bool:
        """
        Determine if custom Internet SmartGroup is required.
        
        A custom Internet SmartGroup is needed when any VPC CIDR is outside
        the standard RFC1918/CGNAT ranges.
        
        Args:
            vpc_cidrs: List of VPC CIDR strings
            
        Returns:
            True if custom Internet SmartGroup is required, False otherwise
        """
        if not vpc_cidrs:
            self.logger.info("No VPC CIDRs provided - no custom Internet SmartGroup needed")
            return False

        non_standard_cidrs = []
        
        for cidr in vpc_cidrs:
            if not self.is_rfc1918_or_cgnat(cidr):
                non_standard_cidrs.append(cidr)

        if non_standard_cidrs:
            self.logger.info(
                f"Found {len(non_standard_cidrs)} non-RFC1918/CGNAT VPC CIDRs: {non_standard_cidrs}"
            )
            self.logger.info("Custom Internet SmartGroup is required")
            return True
        else:
            self.logger.info("All VPC CIDRs are within RFC1918/CGNAT ranges - using standard Internet SmartGroup")
            return False

    def generate_internet_cidr_exclusions(self, vpc_cidrs: List[str]) -> List[str]:
        """
        Generate CIDR ranges representing "Internet minus VPC CIDRs".
        
        This creates a complementary set of CIDRs that covers all Internet
        addresses except the specified VPC CIDRs.
        
        Args:
            vpc_cidrs: List of VPC CIDR strings to exclude from Internet
            
        Returns:
            List of CIDR strings representing Internet space minus VPC CIDRs
        """
        if not vpc_cidrs:
            # No VPC CIDRs to exclude, return full Internet range
            return ["0.0.0.0/0"]

        try:
            # Convert VPC CIDRs to network objects
            vpc_networks = []
            for cidr in vpc_cidrs:
                try:
                    vpc_networks.append(ipaddress.IPv4Network(cidr, strict=False))
                except (ipaddress.AddressValueError, ValueError) as e:
                    self.logger.warning(f"Skipping invalid VPC CIDR {cidr}: {e}")

            if not vpc_networks:
                self.logger.warning("No valid VPC CIDRs found - returning full Internet range")
                return ["0.0.0.0/0"]

            # Start with full IPv4 address space
            internet_space = ipaddress.IPv4Network("0.0.0.0/0")
            
            # Calculate the complementary CIDRs
            remaining_networks = [internet_space]
            
            for vpc_network in vpc_networks:
                new_remaining = []
                for remaining in remaining_networks:
                    # Subtract the VPC network from each remaining network
                    try:
                        complementary = list(remaining.address_exclude(vpc_network))
                        new_remaining.extend(complementary)
                    except ValueError:
                        # Networks don't overlap, keep the original
                        new_remaining.append(remaining)
                remaining_networks = new_remaining

            # Convert back to string list and sort for consistency
            internet_cidrs = [str(network) for network in remaining_networks]
            internet_cidrs.sort()
            
            self.logger.info(f"Generated {len(internet_cidrs)} Internet CIDR exclusions")
            self.logger.debug(f"Internet CIDRs (first 10): {internet_cidrs[:10]}")
            
            return internet_cidrs

        except Exception as e:
            self.logger.error(f"Error generating Internet CIDR exclusions: {e}")
            # Fallback to full Internet range
            return ["0.0.0.0/0"]

    def analyze_vpc_cidr_requirements(self, gateways_df: pd.DataFrame) -> dict:
        """
        Comprehensive analysis of VPC CIDR requirements for custom Internet SmartGroup.
        
        Args:
            gateways_df: DataFrame containing gateway configuration data
            
        Returns:
            Dictionary containing analysis results
        """
        vpc_cidrs = self.extract_vpc_cidrs_from_gateway_data(gateways_df)
        requires_custom = self.requires_custom_internet_smartgroup(vpc_cidrs)
        
        # Categorize CIDRs
        rfc1918_cidrs = []
        cgnat_cidrs = []
        non_standard_cidrs = []
        
        for cidr in vpc_cidrs:
            if self._is_rfc1918(cidr):
                rfc1918_cidrs.append(cidr)
            elif self._is_cgnat(cidr):
                cgnat_cidrs.append(cidr)
            else:
                non_standard_cidrs.append(cidr)

        analysis_result = {
            'vpc_cidrs': vpc_cidrs,
            'requires_custom_internet_smartgroup': requires_custom,
            'rfc1918_cidrs': rfc1918_cidrs,
            'cgnat_cidrs': cgnat_cidrs,
            'non_standard_cidrs': non_standard_cidrs,
            'total_vpc_cidrs': len(vpc_cidrs),
            'internet_cidr_exclusions': self.generate_internet_cidr_exclusions(vpc_cidrs) if requires_custom else []
        }
        
        return analysis_result

    def _is_rfc1918(self, cidr_str: str) -> bool:
        """Check if CIDR is within RFC1918 ranges only."""
        try:
            cidr_network = ipaddress.IPv4Network(cidr_str, strict=False)
            for rfc1918_range in self.RFC1918_RANGES:
                if (cidr_network.subnet_of(rfc1918_range) or 
                    cidr_network.supernet_of(rfc1918_range) or
                    cidr_network.overlaps(rfc1918_range)):
                    return True
            return False
        except (ipaddress.AddressValueError, ValueError):
            return False

    def _is_cgnat(self, cidr_str: str) -> bool:
        """Check if CIDR is within CGNAT ranges only."""
        try:
            cidr_network = ipaddress.IPv4Network(cidr_str, strict=False)
            for cgnat_range in self.CGNAT_RANGES:
                if (cidr_network.subnet_of(cgnat_range) or 
                    cidr_network.supernet_of(cgnat_range) or
                    cidr_network.overlaps(cgnat_range)):
                    return True
            return False
        except (ipaddress.AddressValueError, ValueError):
            return False
