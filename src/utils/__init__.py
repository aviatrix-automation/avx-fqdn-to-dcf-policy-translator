"""
Utility modules for the legacy-to-dcf-policy-translator.

This package contains shared utility functions for data processing,
name cleaning, port translation, and other common operations.
"""

from .data_processing import (
    remove_invalid_name_chars,
    pretty_parse_vpc_name,
    translate_port_to_port_range,
    deduplicate_policy_names,
    is_ipv4
)

__all__ = [
    'remove_invalid_name_chars',
    'pretty_parse_vpc_name', 
    'translate_port_to_port_range',
    'deduplicate_policy_names',
    'is_ipv4'
]
