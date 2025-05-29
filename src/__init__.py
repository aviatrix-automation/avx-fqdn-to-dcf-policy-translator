"""
Legacy-to-DCF Policy Translator Package.

A modular system for converting legacy Aviatrix firewall policies 
to Distributed Cloud Firewall (DCF) format.
"""

__version__ = "1.0.0"
__author__ = "Aviatrix"
__description__ = "Legacy to DCF Policy Translator"

from .config import TranslationConfig

__all__ = [
    'TranslationConfig'
]
