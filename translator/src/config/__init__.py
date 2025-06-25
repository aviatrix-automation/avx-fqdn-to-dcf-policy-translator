"""
Configuration package for the legacy-to-DCF policy translator.
"""

from .defaults import (
    DCF_CONSTRAINTS,
    DEBUG_FILES,
    DEFAULT_DEBUG_DIR,
    DEFAULT_INPUT_DIR,
    DEFAULT_OUTPUT_DIR,
    ENV_VAR_MAPPINGS,
    INVALID_CHARS_REPLACEMENT,
    OUTPUT_FILES,
    POLICY_PRIORITIES,
    TERRAFORM_FILE_PATTERNS,
    get_default_paths,
    get_env_value,
)
from .settings import TranslationConfig

__all__ = [
    "DCF_CONSTRAINTS",
    "DEBUG_FILES",
    "DEFAULT_DEBUG_DIR",
    "DEFAULT_INPUT_DIR",
    "DEFAULT_OUTPUT_DIR",
    "ENV_VAR_MAPPINGS",
    "INVALID_CHARS_REPLACEMENT",
    "OUTPUT_FILES",
    "POLICY_PRIORITIES",
    "TERRAFORM_FILE_PATTERNS",
    "TranslationConfig",
    "get_default_paths",
    "get_env_value",
]
