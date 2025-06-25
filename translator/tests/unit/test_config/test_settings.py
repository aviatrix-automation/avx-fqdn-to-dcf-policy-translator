"""
Unit tests for configuration settings module.

Tests the TranslationConfig class including:
- Initialization with defaults
- Environment variable overrides
- Command line argument processing
- Path management
- Validation
"""

import argparse
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock
import sys

# Add src to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'src'))

from config.settings import TranslationConfig
from config.defaults import TERRAFORM_FILE_PATTERNS, OUTPUT_FILES, DEBUG_FILES


class TestTranslationConfigInitialization:
    """Test basic initialization and defaults."""

    def test_default_initialization(self):
        """Test config initializes with default values."""
        config = TranslationConfig()
        
        # Check that paths are set
        assert isinstance(config.input_dir, Path)
        assert isinstance(config.output_dir, Path)
        assert isinstance(config.debug_dir, Path)
        
        # Check default boolean values
        assert config.enable_debug is False
        assert config.force_overwrite is False
        assert config.validate_only is False
        assert config.skip_unsupported is True
        
        # Check optional fields
        assert config.customer_name is None
        assert config.organization_name is None

    def test_initialization_with_custom_values(self):
        """Test config initialization with custom values."""
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir) / "input"
            output_dir = Path(temp_dir) / "output"
            debug_dir = Path(temp_dir) / "debug"
            
            config = TranslationConfig(
                input_dir=input_dir,
                output_dir=output_dir,
                debug_dir=debug_dir,
                enable_debug=True,
                customer_name="test_customer"
            )
            
            assert config.input_dir == input_dir
            assert config.output_dir == output_dir
            assert config.debug_dir == debug_dir
            assert config.enable_debug is True
            assert config.customer_name == "test_customer"

    def test_path_conversion(self):
        """Test that string paths are converted to Path objects."""
        config = TranslationConfig(
            input_dir="./input",
            output_dir="./output"
        )
        
        assert isinstance(config.input_dir, Path)
        assert isinstance(config.output_dir, Path)

    def test_default_file_patterns_copied(self):
        """Test that default file patterns are properly copied."""
        config = TranslationConfig()
        
        # Should have all expected file patterns
        assert "firewall" in config.terraform_files
        assert "firewall_policy" in config.terraform_files
        assert "gateway_details" in config.terraform_files
        
        # Modifying config shouldn't affect defaults
        config.terraform_files["test"] = "test.tf"
        assert "test" not in TERRAFORM_FILE_PATTERNS


class TestEnvironmentVariableOverrides:
    """Test environment variable processing."""

    def test_env_override_paths(self):
        """Test environment variable overrides for paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_vars = {
                "TRANSLATOR_INPUT_DIR": str(Path(temp_dir) / "env_input"),
                "TRANSLATOR_OUTPUT_DIR": str(Path(temp_dir) / "env_output"),
                "TRANSLATOR_DEBUG_DIR": str(Path(temp_dir) / "env_debug")
            }
            
            with patch.dict(os.environ, env_vars, clear=False):
                config = TranslationConfig()
                
                assert str(config.input_dir).endswith("env_input")
                assert str(config.output_dir).endswith("env_output")
                assert str(config.debug_dir).endswith("env_debug")

    def test_env_override_boolean_flags(self):
        """Test environment variable overrides for boolean flags."""
        test_cases = [
            ("true", True),
            ("1", True),
            ("yes", True),
            ("on", True),
            ("false", False),
            ("0", False),
            ("no", False),
            ("off", False),
            ("", False),
        ]
        
        for env_value, expected in test_cases:
            env_vars = {
                "TRANSLATOR_DEBUG_ENABLED": env_value,
                "TRANSLATOR_FORCE_OVERWRITE": env_value,
                "TRANSLATOR_VALIDATE_ONLY": env_value,
            }
            
            with patch.dict(os.environ, env_vars, clear=False):
                config = TranslationConfig()
                
                assert config.enable_debug == expected
                assert config.force_overwrite == expected
                assert config.validate_only == expected

    def test_env_vars_precedence_over_defaults(self):
        """Test that environment variables take precedence over defaults."""
        with tempfile.TemporaryDirectory() as temp_dir:
            default_dir = Path(temp_dir) / "default"
            env_dir = Path(temp_dir) / "env_override"
            
            env_vars = {"TRANSLATOR_INPUT_DIR": str(env_dir)}
            
            with patch.dict(os.environ, env_vars, clear=False):
                config = TranslationConfig(input_dir=default_dir)
                
                # Environment variable should override the default
                assert config.input_dir == env_dir


class TestFilePathMethods:
    """Test file path resolution methods."""

    def test_get_input_file_path(self):
        """Test getting input file paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = TranslationConfig(input_dir=Path(temp_dir))
            
            firewall_path = config.get_input_file_path("firewall")
            expected_path = Path(temp_dir) / "firewall.tf"
            
            assert firewall_path == expected_path

    def test_get_output_file_path(self):
        """Test getting output file paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = TranslationConfig(output_dir=Path(temp_dir))
            
            smart_groups_path = config.get_output_file_path("smart_groups")
            expected_path = Path(temp_dir) / "aviatrix_smart_group.tf.json"
            
            assert smart_groups_path == expected_path

    def test_get_debug_file_path(self):
        """Test getting debug file paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = TranslationConfig(debug_dir=Path(temp_dir))
            
            clean_policies_path = config.get_debug_file_path("clean_policies")
            expected_path = Path(temp_dir) / "clean_policies.csv"
            
            assert clean_policies_path == expected_path

    def test_invalid_file_key_raises_error(self):
        """Test that invalid file keys raise errors."""
        config = TranslationConfig()
        
        with pytest.raises(ValueError, match="Unknown input file key"):
            config.get_input_file_path("nonexistent")
        
        with pytest.raises(ValueError, match="Unknown output file key"):
            config.get_output_file_path("nonexistent")
        
        with pytest.raises(ValueError, match="Unknown debug file key"):
            config.get_debug_file_path("nonexistent")


class TestDirectoryManagement:
    """Test directory creation and management."""

    def test_ensure_directories_exist(self):
        """Test directory creation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "output"
            debug_dir = Path(temp_dir) / "debug"
            
            config = TranslationConfig(
                output_dir=output_dir,
                debug_dir=debug_dir,
                enable_debug=True
            )
            
            # Directories shouldn't exist yet
            assert not output_dir.exists()
            assert not debug_dir.exists()
            
            config.ensure_directories_exist()
            
            # Now they should exist
            assert output_dir.exists()
            assert debug_dir.exists()

    def test_ensure_directories_debug_disabled(self):
        """Test that debug directory isn't created when debug is disabled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "output"
            debug_dir = Path(temp_dir) / "debug"
            
            config = TranslationConfig(
                output_dir=output_dir,
                debug_dir=debug_dir,
                enable_debug=False
            )
            
            config.ensure_directories_exist()
            
            assert output_dir.exists()
            assert not debug_dir.exists()


class TestFromArgsClassMethod:
    """Test configuration creation from command line arguments."""

    def test_from_args_with_all_arguments(self):
        """Test creating config from complete argument set."""
        with tempfile.TemporaryDirectory() as temp_dir:
            args = argparse.Namespace(
                input_dir=str(Path(temp_dir) / "input"),
                output_dir=str(Path(temp_dir) / "output"),
                debug_dir=str(Path(temp_dir) / "debug"),
                debug=True,
                force=True,
                validate_only=True,
                customer_name="test_customer"
            )
            
            config = TranslationConfig.from_args(args)
            
            assert str(config.input_dir).endswith("input")
            assert str(config.output_dir).endswith("output")
            assert str(config.debug_dir).endswith("debug")
            assert config.enable_debug is True
            assert config.force_overwrite is True
            assert config.validate_only is True
            assert config.customer_name == "test_customer"

    def test_from_args_with_partial_arguments(self):
        """Test creating config from partial argument set."""
        args = argparse.Namespace(
            debug=True,
            customer_name="partial_test"
        )
        
        config = TranslationConfig.from_args(args)
        
        # Should have defaults for missing args
        assert isinstance(config.input_dir, Path)
        assert isinstance(config.output_dir, Path)
        assert config.enable_debug is True
        assert config.force_overwrite is False  # Default
        assert config.customer_name == "partial_test"

    def test_from_args_missing_attributes(self):
        """Test graceful handling of args without expected attributes."""
        args = argparse.Namespace()  # Empty args
        
        config = TranslationConfig.from_args(args)
        
        # Should use all defaults
        assert isinstance(config.input_dir, Path)
        assert config.enable_debug is False
        assert config.customer_name is None


class TestConfigValidation:
    """Test configuration validation."""

    def test_validate_with_existing_files(self):
        """Test validation passes when required files exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            
            # Create required files
            (input_dir / "firewall.tf").touch()
            (input_dir / "firewall_policy.tf").touch()
            (input_dir / "gateway_details.json").touch()
            
            config = TranslationConfig(input_dir=input_dir)
            errors = config.validate()
            
            assert len(errors) == 0

    def test_validate_missing_input_directory(self):
        """Test validation fails when input directory doesn't exist."""
        config = TranslationConfig(input_dir=Path("/nonexistent/directory"))
        errors = config.validate()
        
        assert len(errors) > 0
        assert any("Input directory does not exist" in error for error in errors)

    def test_validate_missing_required_files(self):
        """Test validation fails when required files are missing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = TranslationConfig(input_dir=Path(temp_dir))
            errors = config.validate()
            
            # Should have errors for missing required files
            assert len(errors) >= 3  # At least firewall, firewall_policy, gateway_details
            assert any("firewall.tf" in error for error in errors)
            assert any("firewall_policy.tf" in error for error in errors)
            assert any("gateway_details.json" in error for error in errors)

    def test_validate_partial_files(self):
        """Test validation with some files present."""
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir)
            
            # Create only some required files
            (input_dir / "firewall.tf").touch()
            # Missing firewall_policy.tf and gateway_details.json
            
            config = TranslationConfig(input_dir=input_dir)
            errors = config.validate()
            
            # Should have errors for missing files but not for existing ones
            assert len(errors) == 2  # firewall_policy and gateway_details
            assert not any("firewall.tf" in error for error in errors)
            assert any("firewall_policy.tf" in error for error in errors)
            assert any("gateway_details.json" in error for error in errors)


class TestConfigIntegration:
    """Integration tests for config functionality."""

    def test_full_workflow_with_env_and_args(self):
        """Test complete workflow with environment variables and args."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set environment variables
            env_vars = {
                "TRANSLATOR_DEBUG_ENABLED": "true",
                "TRANSLATOR_INPUT_DIR": str(Path(temp_dir) / "env_input")
            }
            
            # Create args that should override env vars
            args = argparse.Namespace(
                output_dir=str(Path(temp_dir) / "args_output"),
                customer_name="integration_test"
            )
            
            with patch.dict(os.environ, env_vars, clear=False):
                config = TranslationConfig.from_args(args)
                
                # Should use env var for input_dir and debug
                assert str(config.input_dir).endswith("env_input")
                assert config.enable_debug is True
                
                # Should use arg for output_dir and customer_name
                assert str(config.output_dir).endswith("args_output")
                assert config.customer_name == "integration_test"

    def test_config_with_file_operations(self):
        """Test config with actual file operations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            input_dir = Path(temp_dir) / "input"
            output_dir = Path(temp_dir) / "output"
            
            config = TranslationConfig(
                input_dir=input_dir,
                output_dir=output_dir,
                enable_debug=True
            )
            
            # Create input directory and some files
            input_dir.mkdir()
            (input_dir / "firewall.tf").write_text("# test firewall config")
            
            # Ensure directories exist
            config.ensure_directories_exist()
            
            # Test file path resolution
            firewall_path = config.get_input_file_path("firewall")
            assert firewall_path.exists()
            assert firewall_path.read_text() == "# test firewall config"
            
            smart_groups_path = config.get_output_file_path("smart_groups")
            assert smart_groups_path.parent.exists()  # Output dir should exist
