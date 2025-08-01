"""
Configuration management for the legacy-to-DCF policy translator.
"""

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .defaults import (
    DCF_CONSTRAINTS,
    DEBUG_FILES,
    FQDN_SOURCE_IP_CONFIG,
    OUTPUT_FILES,
    POLICY_PRIORITIES,
    TERRAFORM_FILE_PATTERNS,
    get_default_paths,
    get_env_value,
)


@dataclass
class TranslationConfig:
    """Configuration settings for the translation process."""

    # Input/Output directories
    input_dir: Path = field(default_factory=lambda: get_default_paths()["input_dir"])
    output_dir: Path = field(default_factory=lambda: get_default_paths()["output_dir"])
    debug_dir: Path = field(default_factory=lambda: get_default_paths()["debug_dir"])

    # Processing options
    enable_debug: bool = False
    force_overwrite: bool = False
    validate_only: bool = False
    skip_unsupported: bool = True

    # File patterns and names
    terraform_files: Dict[str, str] = field(default_factory=lambda: TERRAFORM_FILE_PATTERNS.copy())
    output_files: Dict[str, str] = field(default_factory=lambda: OUTPUT_FILES.copy())
    debug_files: Dict[str, str] = field(default_factory=lambda: DEBUG_FILES.copy())

    # DCF constraints
    dcf_constraints: Dict[str, Any] = field(default_factory=lambda: DCF_CONSTRAINTS.copy())
    policy_priorities: Dict[str, int] = field(default_factory=lambda: POLICY_PRIORITIES.copy())

    # FQDN Source IP configuration
    fqdn_source_ip_config: Dict[str, Any] = field(default_factory=lambda: FQDN_SOURCE_IP_CONFIG.copy())

    # DCF-specific configuration
    internet_sg_id: str = "def000ad-0000-0000-0000-000000000001"
    anywhere_sg_id: str = "def000ad-0000-0000-0000-000000000000"
    any_webgroup_id: str = "def000ad-0000-0000-0000-000000000002"
    default_web_port_ranges: List[str] = field(default_factory=lambda: ["80", "443"])
    global_catch_all_action: str = "PERMIT"
    loglevel: str = "WARNING"

    # Custom Internet SmartGroup configuration
    enable_custom_internet_smartgroup: bool = True
    custom_internet_smartgroup_name: str = "Internet_Custom"

    # Optional customer/organization context
    customer_name: Optional[str] = None
    organization_name: Optional[str] = None

    def __post_init__(self) -> None:
        """Post-initialization processing."""
        # Ensure paths are Path objects
        self.input_dir = Path(self.input_dir)
        self.output_dir = Path(self.output_dir)
        self.debug_dir = Path(self.debug_dir)

        # Load environment variable overrides
        self._load_env_overrides()

    def _load_env_overrides(self) -> None:
        """Load configuration overrides from environment variables."""
        env_input_dir = get_env_value("input_dir")
        if env_input_dir:
            self.input_dir = Path(env_input_dir)

        env_output_dir = get_env_value("output_dir")
        if env_output_dir:
            self.output_dir = Path(env_output_dir)

        env_debug_dir = get_env_value("debug_dir")
        if env_debug_dir:
            self.debug_dir = Path(env_debug_dir)

        env_debug = get_env_value("enable_debug")
        if env_debug:
            self.enable_debug = env_debug.lower() in ("true", "1", "yes", "on")

        env_force = get_env_value("force_overwrite")
        if env_force:
            self.force_overwrite = env_force.lower() in ("true", "1", "yes", "on")

        env_validate = get_env_value("validate_only")
        if env_validate:
            self.validate_only = env_validate.lower() in ("true", "1", "yes", "on")

        # Load FQDN source IP advanced translation setting
        env_fqdn_advanced = get_env_value("fqdn_source_ip_advanced")
        if env_fqdn_advanced:
            self.fqdn_source_ip_config["enable_advanced_translation"] = env_fqdn_advanced.lower() in ("true", "1", "yes", "on")

    def get_input_file_path(self, file_key: str) -> Path:
        """Get the full path for an input file."""
        filename = self.terraform_files.get(file_key)
        if not filename:
            raise ValueError(f"Unknown input file key: {file_key}")
        return self.input_dir / filename

    def get_output_file_path(self, file_key: str) -> Path:
        """Get the full path for an output file."""
        filename = self.output_files.get(file_key)
        if not filename:
            raise ValueError(f"Unknown output file key: {file_key}")
        return self.output_dir / filename

    def get_debug_file_path(self, file_key: str) -> Path:
        """Get the full path for a debug file."""
        filename = self.debug_files.get(file_key)
        if not filename:
            raise ValueError(f"Unknown debug file key: {file_key}")
        return self.debug_dir / filename

    def ensure_directories_exist(self) -> None:
        """Create necessary directories if they don't exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.enable_debug:
            self.debug_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "TranslationConfig":
        """Create configuration from command line arguments."""
        config = cls()

        # Override with command line arguments if provided
        if hasattr(args, "input_dir") and args.input_dir:
            config.input_dir = Path(args.input_dir)
        if hasattr(args, "output_dir") and args.output_dir:
            config.output_dir = Path(args.output_dir)
        if hasattr(args, "debug_dir") and args.debug_dir:
            config.debug_dir = Path(args.debug_dir)
        if hasattr(args, "debug") and args.debug:
            config.enable_debug = args.debug
        if hasattr(args, "force") and args.force:
            config.force_overwrite = args.force
        if hasattr(args, "validate_only") and args.validate_only:
            config.validate_only = args.validate_only
        if hasattr(args, "customer_name") and args.customer_name:
            config.customer_name = args.customer_name

        return config

    def validate(self) -> List[str]:
        """Validate the configuration and return any errors."""
        errors = []

        # Check if input directory exists
        if not self.input_dir.exists():
            errors.append(f"Input directory does not exist: {self.input_dir}")

        # Check for required input files
        required_files = ["firewall", "firewall_policy", "gateway_details"]
        for file_key in required_files:
            file_path = self.get_input_file_path(file_key)
            if not file_path.exists():
                errors.append(f"Required input file not found: {file_path}")

        return errors

    def get_fqdn_source_ip_advanced_translation(self) -> bool:
        """Get whether advanced FQDN source IP translation is enabled."""
        return self.fqdn_source_ip_config.get("enable_advanced_translation", True)

    def set_fqdn_source_ip_advanced_translation(self, enabled: bool) -> None:
        """Set whether advanced FQDN source IP translation is enabled."""
        self.fqdn_source_ip_config["enable_advanced_translation"] = enabled

    def get_fqdn_source_ip_simple_suffix(self) -> str:
        """Get the suffix for simple FQDN source IP SmartGroups."""
        return self.fqdn_source_ip_config.get("simple_smartgroup_suffix", "_source_ips")

    def get_fqdn_source_ip_asset_suffix(self) -> str:
        """Get the suffix for asset-based FQDN source IP SmartGroups."""
        return self.fqdn_source_ip_config.get("asset_smartgroup_suffix", "_asset")

    def get_fqdn_source_ip_policy_priority_offset(self) -> int:
        """Get the policy priority offset for FQDN source IP policies."""
        return self.fqdn_source_ip_config.get("policy_priority_offset", 50)
