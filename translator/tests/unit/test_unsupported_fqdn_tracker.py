"""
Unit tests for UnsupportedFQDNTracker and UnsupportedFQDNRecord.
"""

import logging
import unittest
from unittest.mock import patch

import pandas as pd

from src.domain.constants import UnsupportedFQDNRecord
from src.translation.unsupported_fqdn_tracker import UnsupportedFQDNTracker


class TestUnsupportedFQDNRecord(unittest.TestCase):
    """Test cases for UnsupportedFQDNRecord dataclass."""

    def test_record_creation(self):
        """Test creating an UnsupportedFQDNRecord."""
        record = UnsupportedFQDNRecord(
            fqdn_tag_name="Test Tag",
            webgroup_name="Test WebGroup",
            domain="*.example.com",
            port="443",
            protocol="TCP",
            reason="DCF 8.0 incompatible SNI domain pattern"
        )
        
        self.assertEqual(record.fqdn_tag_name, "Test Tag")
        self.assertEqual(record.webgroup_name, "Test WebGroup")
        self.assertEqual(record.domain, "*.example.com")
        self.assertEqual(record.port, "443")
        self.assertEqual(record.protocol, "TCP")
        self.assertEqual(record.reason, "DCF 8.0 incompatible SNI domain pattern")


class TestUnsupportedFQDNTracker(unittest.TestCase):
    """Test cases for UnsupportedFQDNTracker class."""

    def setUp(self):
        """Set up test fixtures."""
        self.tracker = UnsupportedFQDNTracker()

    def test_initial_state(self):
        """Test tracker initial state."""
        self.assertEqual(self.tracker.get_total_count(), 0)
        self.assertEqual(self.tracker.get_affected_webgroups_count(), 0)
        self.assertEqual(self.tracker.get_affected_fqdn_tags_count(), 0)
        self.assertEqual(self.tracker.get_summary_by_reason(), {})

    def test_add_record(self):
        """Test adding a record to the tracker."""
        record = UnsupportedFQDNRecord(
            fqdn_tag_name="Test Tag",
            webgroup_name="Test WebGroup",
            domain="*.example.com",
            port="443",
            protocol="TCP",
            reason="DCF 8.0 incompatible SNI domain pattern"
        )
        
        self.tracker.add_record(record)
        
        self.assertEqual(self.tracker.get_total_count(), 1)
        self.assertEqual(self.tracker.get_affected_webgroups_count(), 1)
        self.assertEqual(self.tracker.get_affected_fqdn_tags_count(), 1)

    def test_add_invalid_domain(self):
        """Test adding an invalid domain using convenience method."""
        self.tracker.add_invalid_domain(
            fqdn_tag_name="Test Tag",
            webgroup_name="Test WebGroup",
            domain="*.example.com",
            port="443",
            protocol="TCP",
            reason="DCF 8.0 incompatible SNI domain pattern"
        )
        
        self.assertEqual(self.tracker.get_total_count(), 1)
        self.assertEqual(len(self.tracker.records), 1)
        
        record = self.tracker.records[0]
        self.assertEqual(record.fqdn_tag_name, "Test Tag")
        self.assertEqual(record.domain, "*.example.com")

    def test_multiple_records(self):
        """Test adding multiple records."""
        # Add records from different webgroups and tags
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.example.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.test.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag2", "WebGroup2", "*.another.com", "80", "TCP", "DCF 8.0 incompatible")
        
        self.assertEqual(self.tracker.get_total_count(), 3)
        self.assertEqual(self.tracker.get_affected_webgroups_count(), 2)
        self.assertEqual(self.tracker.get_affected_fqdn_tags_count(), 2)

    def test_summary_by_reason(self):
        """Test getting summary by reason."""
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.example.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag2", "WebGroup2", "*.test.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag3", "WebGroup3", "192.168.1.1", "443", "TCP", "IP address in FQDN field")
        
        summary = self.tracker.get_summary_by_reason()
        
        self.assertEqual(summary["DCF 8.0 incompatible"], 2)
        self.assertEqual(summary["IP address in FQDN field"], 1)

    def test_summary_by_webgroup(self):
        """Test getting summary by webgroup."""
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.example.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.test.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag2", "WebGroup2", "*.another.com", "80", "TCP", "DCF 8.0 incompatible")
        
        summary = self.tracker.get_summary_by_webgroup()
        
        self.assertEqual(summary["WebGroup1"], 2)
        self.assertEqual(summary["WebGroup2"], 1)

    def test_top_rejected_domains(self):
        """Test getting top rejected domains."""
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.example.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.example.com", "80", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag2", "WebGroup2", "*.test.com", "443", "TCP", "DCF 8.0 incompatible")
        
        top_domains = self.tracker.get_top_rejected_domains(5)
        
        self.assertEqual(len(top_domains), 2)
        self.assertEqual(top_domains[0]["domain"], "*.example.com")
        self.assertEqual(top_domains[0]["count"], 2)
        self.assertEqual(top_domains[1]["domain"], "*.test.com")
        self.assertEqual(top_domains[1]["count"], 1)

    def test_comprehensive_summary(self):
        """Test getting comprehensive summary."""
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.example.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag2", "WebGroup2", "*.test.com", "443", "TCP", "DCF 8.0 incompatible")
        
        summary = self.tracker.get_comprehensive_summary()
        
        self.assertEqual(summary["total_count"], 2)
        self.assertEqual(summary["affected_webgroups"], 2)
        self.assertEqual(summary["affected_fqdn_tags"], 2)
        self.assertIn("by_reason", summary)
        self.assertIn("by_webgroup", summary)
        self.assertIn("top_rejected_domains", summary)

    def test_to_dataframe(self):
        """Test converting records to DataFrame."""
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.example.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag2", "WebGroup2", "*.test.com", "80", "TCP", "DCF 8.0 incompatible")
        
        df = self.tracker.to_dataframe()
        
        self.assertEqual(len(df), 2)
        self.assertIn("fqdn_tag_name", df.columns)
        self.assertIn("webgroup_name", df.columns)
        self.assertIn("domain", df.columns)
        self.assertIn("port", df.columns)
        self.assertIn("protocol", df.columns)
        self.assertIn("reason", df.columns)
        
        # Check first row
        self.assertEqual(df.iloc[0]["fqdn_tag_name"], "Tag1")
        self.assertEqual(df.iloc[0]["domain"], "*.example.com")

    def test_to_dataframe_empty(self):
        """Test converting empty tracker to DataFrame."""
        df = self.tracker.to_dataframe()
        
        self.assertEqual(len(df), 0)
        self.assertIn("fqdn_tag_name", df.columns)
        self.assertIn("webgroup_name", df.columns)
        self.assertIn("domain", df.columns)

    def test_log_summary(self):
        """Test logging summary."""
        from unittest.mock import Mock
        
        # Mock the logger directly on the instance
        mock_logger = Mock()
        self.tracker._logger = mock_logger
        
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.example.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag2", "WebGroup2", "*.test.com", "443", "TCP", "DCF 8.0 incompatible")
        
        self.tracker.log_summary()
        
        # Verify that log messages were called - the summary method calls log() multiple times
        self.assertTrue(mock_logger.log.called)
        # Should have multiple log calls for comprehensive summary
        self.assertGreaterEqual(mock_logger.log.call_count, 5)

    def test_log_summary_empty(self):
        """Test logging summary with empty tracker."""
        from unittest.mock import Mock
        
        # Mock the logger directly on the instance
        mock_logger = Mock()
        self.tracker._logger = mock_logger
        
        self.tracker.log_summary()
        
        # Should log that no unsupported domains were found
        mock_logger.log.assert_called_once()
        args, kwargs = mock_logger.log.call_args
        self.assertEqual(args[0], logging.INFO)  # log level
        self.assertIn("No unsupported FQDN domains found", args[1])

    def test_clear(self):
        """Test clearing all records."""
        self.tracker.add_invalid_domain("Tag1", "WebGroup1", "*.example.com", "443", "TCP", "DCF 8.0 incompatible")
        self.tracker.add_invalid_domain("Tag2", "WebGroup2", "*.test.com", "443", "TCP", "DCF 8.0 incompatible")
        
        self.assertEqual(self.tracker.get_total_count(), 2)
        
        self.tracker.clear()
        
        self.assertEqual(self.tracker.get_total_count(), 0)
        self.assertEqual(len(self.tracker.records), 0)


if __name__ == '__main__':
    unittest.main()