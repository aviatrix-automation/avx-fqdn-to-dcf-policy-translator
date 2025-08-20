#!/usr/bin/env python3
"""
Test for the hostname SmartGroup name mapping fix.

This test verifies that hostname SmartGroups with FQDN tag names containing spaces
are correctly referenced in policies.
"""

import unittest
from unittest.mock import MagicMock
import pandas as pd
import sys
from pathlib import Path

# Add the src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from config import TranslationConfig
from translation.smartgroups import SmartGroupBuilder
from translation.policies import InternetPolicyBuilder


class TestHostnameSmartGroupNameMappingFix(unittest.TestCase):
    """Test the fix for hostname SmartGroup name mapping with spaces."""

    def setUp(self):
        """Set up test data with FQDN tag names containing spaces."""
        self.config = TranslationConfig()
        self.internet_sg_id = "def000ad-0000-0000-0000-000000000001"
        self.anywhere_sg_id = "def000ad-0000-0000-0000-000000000000"
        self.any_webgroup_id = "def000ad-0000-0000-0000-000000000002"
        self.default_web_port_ranges = ["80", "443"]
        
        # Create test data with FQDN tag names that contain spaces and special chars
        self.hostname_rules_df = pd.DataFrame({
            'fqdn_tag_name': [
                'Sales Team FQDN',  # Contains space
                'Dev-Environment',   # Contains hyphen
                'API Gateway Prod',  # Contains space
                'Sales Team FQDN'    # Duplicate to test grouping
            ],
            'fqdn': [
                'crm.salesforce.com',
                'dev-api.company.com', 
                'api.production.com',
                'erp.salesforce.com'
            ],
            'protocol': ['tcp', 'tcp', 'tcp', 'tcp'],
            'port': ['443', '8080', '443', '443'],
            'fqdn_mode': ['white', 'white', 'white', 'white']
        })
        
        # Create FQDN tags with source IP filters
        self.fqdn_df = pd.DataFrame({
            'fqdn_tag': ['Sales Team FQDN', 'Dev-Environment', 'API Gateway Prod'],
            'fqdn_enabled': [True, True, True],
            'fqdn_mode': ['white', 'white', 'white'],
            'has_source_ip_filter': [True, False, True]  # Sales Team and API Gateway have source IP filters
        })

    def test_hostname_smartgroup_name_extraction_fix(self):
        """Test that hostname SmartGroup names with spaces are correctly mapped to policies."""
        
        # Create hostname SmartGroups using the SmartGroupBuilder
        sg_builder = SmartGroupBuilder(self.config)
        hostname_smartgroups_df = sg_builder.build_hostname_smartgroups(self.hostname_rules_df)
        
        # Verify SmartGroups were created
        self.assertGreater(len(hostname_smartgroups_df), 0, "SmartGroups should be created")
        
        # Verify that original_fqdn_tag_name is stored
        self.assertIn('original_fqdn_tag_name', hostname_smartgroups_df.columns)
        
        # Check that SmartGroup names are cleaned (spaces converted to underscores)
        for _, sg_row in hostname_smartgroups_df.iterrows():
            sg_name = sg_row['name']
            original_fqdn_tag_name = sg_row['original_fqdn_tag_name']
            
            # SmartGroup name should not contain spaces (cleaned)
            self.assertNotIn(' ', sg_name, f"SmartGroup name '{sg_name}' should not contain spaces")
            
            # But original_fqdn_tag_name should preserve the original
            if original_fqdn_tag_name in ['Sales Team FQDN', 'API Gateway Prod']:
                self.assertIn(' ', original_fqdn_tag_name, f"Original name should preserve spaces: {original_fqdn_tag_name}")
        
        # Create policy builder 
        policy_builder = InternetPolicyBuilder(
            self.internet_sg_id,
            self.anywhere_sg_id,
            self.default_web_port_ranges,
            self.any_webgroup_id
        )
        
        # Test source IP hostname policies (for FQDN tags with source IP filters)
        source_ip_policies_df = policy_builder._build_source_ip_hostname_policies(
            self.fqdn_df,
            hostname_smartgroups_df,
            self.hostname_rules_df
        )
        
        # There should be policies created for FQDN tags with source IP filters
        self.assertGreater(len(source_ip_policies_df), 0, "Source IP hostname policies should be created")
        
        # Verify that policies reference the correct SmartGroups
        for _, policy in source_ip_policies_df.iterrows():
            dst_smart_groups = policy['dst_smart_groups']
            self.assertEqual(len(dst_smart_groups), 1, "Should have exactly one destination SmartGroup")
            
            dst_sg_ref = dst_smart_groups[0]
            # Should be a proper terraform reference
            self.assertTrue(dst_sg_ref.startswith("${aviatrix_smart_group."))
            self.assertTrue(dst_sg_ref.endswith(".id}"))
            
            # Extract the SmartGroup name from the reference
            sg_name = dst_sg_ref.replace("${aviatrix_smart_group.", "").replace(".id}", "")
            
            # Verify this SmartGroup name exists in our created SmartGroups
            matching_sgs = hostname_smartgroups_df[hostname_smartgroups_df['name'] == sg_name]
            self.assertEqual(len(matching_sgs), 1, f"Policy references non-existent SmartGroup: {sg_name}")

    def test_name_extraction_backward_compatibility(self):
        """Test that the fallback name extraction logic still works for older SmartGroups."""
        
        # Create a hostname SmartGroup DataFrame without original_fqdn_tag_name column (old format)
        old_format_sg_df = pd.DataFrame({
            'name': ['fqdn_Sales_Team_FQDN_1234'],
            'selector': [{'match_expressions': [{'fqdn': 'example.com'}]}],
            'protocol': ['tcp'],
            'port': ['443'],
            'fqdn_mode': ['white'],
            'fqdn_list': [['example.com']]
        })
        
        # Create policy builder 
        policy_builder = InternetPolicyBuilder(
            self.internet_sg_id,
            self.anywhere_sg_id,
            self.default_web_port_ranges,
            self.any_webgroup_id
        )
        
        # Create simple FQDN and hostname rules data
        simple_fqdn_df = pd.DataFrame({
            'fqdn_tag': ['Sales Team FQDN'],
            'fqdn_enabled': [True],
            'fqdn_mode': ['white'],
            'has_source_ip_filter': [True]
        })
        
        simple_hostname_rules_df = pd.DataFrame({
            'fqdn_tag_name': ['Sales Team FQDN'],
            'fqdn': ['example.com'],
            'protocol': ['tcp'],
            'port': ['443'],
            'fqdn_mode': ['white']
        })
        
        # The method should handle the old format gracefully (though it might not work perfectly)
        # This test ensures we don't crash on old format data
        try:
            source_ip_policies_df = policy_builder._build_source_ip_hostname_policies(
                simple_fqdn_df,
                old_format_sg_df,
                simple_hostname_rules_df
            )
            # The old logic might not create policies due to name mismatch, but shouldn't crash
            self.assertIsInstance(source_ip_policies_df, pd.DataFrame)
        except Exception as e:
            self.fail(f"Backward compatibility test failed with exception: {e}")


if __name__ == '__main__':
    unittest.main()
