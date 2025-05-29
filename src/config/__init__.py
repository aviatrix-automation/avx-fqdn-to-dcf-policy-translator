"""
Configuration package for the legacy-to-DCF policy translator.
"""

from .settings import TranslationConfig
from .defaults import (
    DEFAULT_INPUT_DIR,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_DEBUG_DIR,
    TERRAFORM_FILE_PATTERNS,
    OUTPUT_FILES,
    DEBUG_FILES,
    DCF_CONSTRAINTS,
    POLICY_PRIORITIES,
    ENV_VAR_MAPPINGS,
    INVALID_CHARS_REPLACEMENT,
    get_env_value,
    get_default_paths
)

__all__ = [
    'TranslationConfig',
    'DEFAULT_INPUT_DIR',
    'DEFAULT_OUTPUT_DIR', 
    'DEFAULT_DEBUG_DIR',
    'TERRAFORM_FILE_PATTERNS',
    'OUTPUT_FILES',
    'DEBUG_FILES',
    'DCF_CONSTRAINTS',
    'POLICY_PRIORITIES',
    'ENV_VAR_MAPPINGS',
    'INVALID_CHARS_REPLACEMENT',
    'get_env_value',
    'get_default_paths'
]
