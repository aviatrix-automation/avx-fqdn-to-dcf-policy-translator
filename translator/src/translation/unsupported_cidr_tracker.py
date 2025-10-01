"""
Tracker for CIDR/IP entries found in FQDN fields during DCF translation.

This module handles tracking of CIDR blocks and IP addresses that appear in FQDN 
fields but cannot be used in SNI filters for web groups.
"""

import logging
from collections import defaultdict
from dataclasses import asdict
from typing import Dict, List, Optional

import pandas as pd

from domain.constants import UnsupportedCIDRRecord


class UnsupportedCIDRTracker:
    """
    Centralized tracker for CIDR/IP entries found in FQDN fields during DCF translation.
    
    This class collects and manages details about CIDR blocks and IP addresses that are
    filtered out from web groups during the translation process, providing comprehensive
    reporting and analysis capabilities.
    """
    
    def __init__(self):
        """Initialize the tracker with empty collections."""
        self.records: List[UnsupportedCIDRRecord] = []
        self._logger = logging.getLogger(__name__)
    
    def add_record(self, record: UnsupportedCIDRRecord) -> None:
        """
        Add an unsupported CIDR record to the tracker.
        
        Args:
            record: The UnsupportedCIDRRecord to add
        """
        self.records.append(record)
        self._logger.debug(f"Added unsupported CIDR record: {record.cidr_entry} for {record.webgroup_name}")
    
    def add_cidr_entry(
        self,
        fqdn_tag_name: str,
        webgroup_name: str,
        cidr_entry: str,
        port: str,
        protocol: str,
        entry_type: str,
        reason: str = "CIDR/IP notation not supported in SNI filters"
    ) -> None:
        """
        Add a CIDR/IP entry record with individual parameters.
        
        Args:
            fqdn_tag_name: The name of the FQDN tag
            webgroup_name: The name of the webgroup
            cidr_entry: The CIDR block or IP address
            port: The port number
            protocol: The protocol (TCP/UDP)
            entry_type: The type of entry ("CIDR" or "IP")
            reason: The reason for rejection
        """
        record = UnsupportedCIDRRecord(
            fqdn_tag_name=fqdn_tag_name,
            webgroup_name=webgroup_name,
            cidr_entry=cidr_entry,
            port=port,
            protocol=protocol,
            entry_type=entry_type,
            reason=reason
        )
        self.add_record(record)
    
    def get_total_count(self) -> int:
        """Get the total number of unsupported CIDR entries."""
        return len(self.records)
    
    def get_affected_webgroups_count(self) -> int:
        """Get the number of unique webgroups affected by unsupported CIDR entries."""
        return len(set(record.webgroup_name for record in self.records))
    
    def get_affected_fqdn_tags_count(self) -> int:
        """Get the number of unique FQDN tags affected by unsupported CIDR entries."""
        return len(set(record.fqdn_tag_name for record in self.records))
    
    def get_summary_by_type(self) -> Dict[str, int]:
        """
        Get a summary of unsupported entries grouped by type (CIDR vs IP).
        
        Returns:
            Dictionary mapping entry types to counts
        """
        type_counts = defaultdict(int)
        for record in self.records:
            type_counts[record.entry_type] += 1
        return dict(type_counts)
    
    def get_summary_by_webgroup(self) -> Dict[str, int]:
        """
        Get a summary of unsupported CIDR entries grouped by webgroup.
        
        Returns:
            Dictionary mapping webgroup names to counts
        """
        webgroup_counts = defaultdict(int)
        for record in self.records:
            webgroup_counts[record.webgroup_name] += 1
        return dict(webgroup_counts)
    
    def get_summary_by_fqdn_tag(self) -> Dict[str, int]:
        """
        Get a summary of unsupported CIDR entries grouped by FQDN tag.
        
        Returns:
            Dictionary mapping FQDN tag names to counts
        """
        tag_counts = defaultdict(int)
        for record in self.records:
            tag_counts[record.fqdn_tag_name] += 1
        return dict(tag_counts)
    
    def get_top_cidr_entries(self, limit: int = 10) -> List[Dict[str, int]]:
        """
        Get the most frequently occurring CIDR entries.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of dictionaries with cidr_entry and count
        """
        cidr_counts = defaultdict(int)
        for record in self.records:
            cidr_counts[record.cidr_entry] += 1
        
        sorted_cidrs = sorted(cidr_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"cidr_entry": cidr, "count": count} for cidr, count in sorted_cidrs[:limit]]
    
    def get_comprehensive_summary(self) -> Dict[str, any]:
        """
        Get a comprehensive summary of all unsupported CIDR statistics.
        
        Returns:
            Dictionary with detailed statistics
        """
        return {
            "total_count": self.get_total_count(),
            "affected_webgroups": self.get_affected_webgroups_count(),
            "affected_fqdn_tags": self.get_affected_fqdn_tags_count(),
            "by_type": self.get_summary_by_type(),
            "by_webgroup": self.get_summary_by_webgroup(),
            "by_fqdn_tag": self.get_summary_by_fqdn_tag(),
            "top_cidr_entries": self.get_top_cidr_entries(10)
        }
    
    def to_dataframe(self) -> pd.DataFrame:
        """
        Convert all records to a pandas DataFrame for CSV export.
        
        Returns:
            DataFrame with all unsupported CIDR records
        """
        if not self.records:
            # Return empty DataFrame with proper columns
            return pd.DataFrame(columns=[
                "fqdn_tag_name", "webgroup_name", "cidr_entry", "port", "protocol", "entry_type", "reason"
            ])
        
        return pd.DataFrame([asdict(record) for record in self.records])
    
    def log_summary(self, log_level: int = logging.INFO) -> None:
        """
        Log a comprehensive summary of unsupported CIDR entries.
        
        Args:
            log_level: The logging level to use
        """
        if not self.records:
            self._logger.log(log_level, "No unsupported CIDR entries found during translation")
            return
        
        summary = self.get_comprehensive_summary()
        
        self._logger.log(log_level, f"=== Unsupported CIDR Entries Summary ===")
        self._logger.log(log_level, f"Total unsupported CIDR entries: {summary['total_count']}")
        self._logger.log(log_level, f"Affected webgroups: {summary['affected_webgroups']}")
        self._logger.log(log_level, f"Affected FQDN tags: {summary['affected_fqdn_tags']}")
        
        self._logger.log(log_level, "Breakdown by type:")
        for entry_type, count in summary['by_type'].items():
            self._logger.log(log_level, f"  {entry_type}: {count} entries")
        
        self._logger.log(log_level, "Top 5 most affected webgroups:")
        sorted_webgroups = sorted(summary['by_webgroup'].items(), key=lambda x: x[1], reverse=True)
        for webgroup, count in sorted_webgroups[:5]:
            self._logger.log(log_level, f"  {webgroup}: {count} entries")
        
        self._logger.log(log_level, "Top 5 most common CIDR entries:")
        for entry_info in summary['top_cidr_entries'][:5]:
            self._logger.log(log_level, f"  {entry_info['cidr_entry']}: {entry_info['count']} occurrences")
        
        self._logger.log(log_level, "=== End Unsupported CIDR Summary ===")
    
    def clear(self) -> None:
        """Clear all records from the tracker."""
        self.records.clear()
        self._logger.debug("Cleared all unsupported CIDR records")