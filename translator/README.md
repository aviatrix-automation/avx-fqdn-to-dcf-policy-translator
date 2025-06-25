# Legacy to DCF Policy Translator

This directory contains the policy translation tools for converting legacy Aviatrix firewall and FQDN policies to Distributed Cloud Firewall (DCF) format.

## Files and Structure

### Source Code
- **`src/`**: Modular translator implementation
  - **`main.py`**: Primary entry point with comprehensive CLI options
  - **`config/`**: Configuration management and default values
  - **`data/`**: Data loading, processing, cleaning, and export functionality
  - **`translation/`**: Policy translation engines (L4, FQDN, SmartGroups, WebGroups)
  - **`analysis/`**: Policy validation, FQDN analysis, and translation reporting
  - **`utils/`**: Utility functions and helper methods
  - **`domain/`**: Domain models, constants, and validation logic

### Legacy Script
- **`translator.py`**: Original monolithic script (maintained for backward compatibility)

### Testing
- **`tests/`**: Comprehensive test suite
  - **`unit/`**: Unit tests for all modules
  - **`fixtures/`**: Test data and expected outputs
  - **`conftest.py`**: Pytest configuration

## Installation

Install dependencies from the project root:

```bash
cd ..
pip install -r requirements.txt          # Production dependencies
pip install -r requirements-dev.txt     # Development dependencies (includes testing)
```

## Usage

### Primary Entry Point (Recommended)
```bash
# Basic translation with default settings
python src/main.py

# Custom directories and customer context
python src/main.py --input-dir ./input --output-dir ./output --customer-name "Example Corp"

# Debug mode with detailed logging
python src/main.py --debug --loglevel INFO

# Validation only (no output generation)
python src/main.py --validate-only --loglevel INFO

# Custom DCF configuration
python src/main.py --global-catch-all-action DENY --any-webgroup-id "custom-webgroup-id"
```

### Legacy Entry Point (Alternative)
```bash
python translator.py [options]
```

## Key Options

### Directory Configuration
- `--input-dir`: Path to input files (default: ./input)
- `--output-dir`: Path for output files (default: ./output)
- `--debug-dir`: Path for debug files (default: ./debug)

### Processing Options
- `--debug`: Enable debug mode with detailed output and debug files
- `--force`: Force overwrite existing output files
- `--validate-only`: Only validate input files without generating output
- `--customer-name`: Customer name for naming context

### DCF Configuration
- `--internet-sg-id`: Internet security group ID
- `--anywhere-sg-id`: Anywhere security group ID
- `--any-webgroup-id`: Any webgroup ID
- `--default-web-port-ranges`: Default web port ranges (default: 80 443)
- `--global-catch-all-action {PERMIT,DENY}`: Global catch-all action (default: PERMIT)

### Logging
- `--loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}`: Set logging level (default: WARNING)

## Input Requirements

1. **Policy Bundle**: Extract the policy bundle from the exporter into the `./input` directory
2. **Directory Structure**: Create `./input`, `./output`, and optionally `./debug` directories
3. **Any-Web ID**: Obtain the "Any Webgroup" ID from your target controller (v7.1+)

## Output Files

### Terraform Configuration
- `aviatrix_distributed_firewall_policy_list.tf.json`: DCF rule list
- `aviatrix_smart_group.tf.json`: SmartGroups (CIDR, VPC, and FQDN-based)
- `aviatrix_web_group.tf.json`: WebGroups for HTTP/HTTPS traffic
- `main.tf`: Complete Terraform configuration

### Review Files
- `smartgroups.csv`: SmartGroup configuration summary
- `full_policy_list.csv`: Complete translated policy list
- `unsupported_fqdn_rules.csv`: Rules requiring manual configuration
- `removed_duplicate_policies.csv`: Optimized duplicate policies

## Development

### Testing
```bash
# Run all tests (from project root)
pytest translator/tests/

# Run specific test categories
pytest translator/tests/unit/test_translation/
pytest translator/tests/unit/test_analysis/

# Run with coverage
pytest --cov translator/tests/
```

### Linting and Type Checking
```bash
# From project root
ruff check .
ruff format .
mypy .
```

## Architecture

The translator uses a modular architecture with clear separation of concerns:

1. **Data Processing Pipeline**: Load → Clean → Transform → Export
2. **Translation Engines**: Specialized handlers for different policy types
3. **Validation & Analysis**: Comprehensive validation and reporting
4. **Graceful Error Handling**: Robust error handling with detailed logging

## Key Features

- **Automatic Deduplication**: Eliminates duplicate policies across gateways
- **DCF 8.0 Compatibility**: SNI domain validation and filtering
- **Comprehensive Reporting**: Detailed translation reports and CSV summaries
- **Character Consistency**: Unified character cleaning across all components
- **Flexible Configuration**: Extensive CLI options for customization

## Requirements

- Python 3.8+
- Input policy bundle from the exporter tool
- Valid "Any-Web" webgroup ID from target controller
- Appropriate directory permissions for file creation