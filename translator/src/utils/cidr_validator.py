"""
CIDR notation validation utilities for the legacy-to-DCF policy translator.

This module provides functionality to detect and handle CIDR notation in FQDN fields,
which are invalid for SNI filters in web groups.
"""

import ipaddress
import re
from typing import List, Tuple


class CIDRValidator:
    """Validates and filters CIDR notation from domain lists."""

    # Pattern to match IPv4 CIDR notation (e.g., 192.168.1.1/24, 10.0.0.0/8)
    CIDR_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')

    @staticmethod
    def is_cidr_notation(value: str) -> bool:
        """
        Check if a string represents CIDR notation.

        Args:
            value: String to check

        Returns:
            True if the value is CIDR notation, False otherwise
        """
        if not value or not isinstance(value, str):
            return False

        value = value.strip()
        
        # First check with regex for performance
        if not CIDRValidator.CIDR_PATTERN.match(value):
            return False

        # Validate it's actually a valid CIDR block
        try:
            ipaddress.IPv4Network(value, strict=False)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_ip_address(value: str) -> bool:
        """
        Check if a string represents an IP address (without CIDR notation).

        Args:
            value: String to check

        Returns:
            True if the value is an IP address, False otherwise
        """
        if not value or not isinstance(value, str):
            return False

        value = value.strip()
        
        # Check if it looks like an IP address (no slash)
        if '/' in value:
            return False

        try:
            ipaddress.IPv4Address(value)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def filter_cidr_notation(
        fqdn_list: List[str], 
        context_name: str = None
    ) -> Tuple[List[str], List[str]]:
        """
        Filter CIDR notation from FQDN list. IP addresses are valid in SNI filters.

        Args:
            fqdn_list: List of domain strings that may contain CIDR entries
            context_name: Name for logging context (optional)

        Returns:
            Tuple of (valid_domains, invalid_entries)
            - valid_domains: List of actual domain names and IP addresses
            - invalid_entries: List of CIDR blocks that were filtered out
        """
        valid_domains = []
        invalid_entries = []

        for entry in fqdn_list:
            if CIDRValidator.is_cidr_notation(entry):
                invalid_entries.append(entry)
            else:
                valid_domains.append(entry)

        return valid_domains, invalid_entries