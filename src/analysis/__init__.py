"""
Analysis module for the legacy-to-DCF policy translator.

This module contains classes and functions for analyzing FQDN rules,
generating statistics, and reporting on translation results.
"""

# Make analysis functions available at module level
from .fqdn_analysis import *
from .policy_validators import *
from .translation_reporter import *

__all__ = [
    'FQDNAnalyzer',
    'FQDNCategorizer', 
    'DomainCompatibilityAnalyzer',
    'PolicyValidator',
    'TranslationReporter'
]
