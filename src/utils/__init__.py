"""
Utility modules for the legacy-to-dcf-policy-translator.

This package contains shared utility functions for data processing,
name cleaning, port translation, and other common operations.
"""

from .data_processing import (
    deduplicate_policy_names,
    is_ipv4,
    pretty_parse_vpc_name,
    remove_invalid_name_chars,
    translate_port_to_port_range,
)

__all__ = [
    "deduplicate_policy_names",
    "is_ipv4",
    "pretty_parse_vpc_name",
    "remove_invalid_name_chars",
    "translate_port_to_port_range",
]
