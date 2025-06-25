"""
Analysis module for the legacy-to-DCF policy translator.

This module contains classes and functions for analyzing FQDN rules,
generating statistics, and reporting on translation results.
"""

# Import specific classes instead of using star imports
from .fqdn_analysis import (
    DomainCompatibilityAnalyzer,
    FQDNAnalysisResult,
    FQDNAnalyzer,
    FQDNCategorizer,
)
from .policy_validators import PolicyValidator, ValidationResult
from .translation_reporter import TranslationReporter, TranslationStats

__all__ = [
    "DomainCompatibilityAnalyzer",
    "FQDNAnalysisResult",
    "FQDNAnalyzer",
    "FQDNCategorizer",
    "PolicyValidator",
    "TranslationReporter",
    "TranslationStats",
    "ValidationResult",
]
