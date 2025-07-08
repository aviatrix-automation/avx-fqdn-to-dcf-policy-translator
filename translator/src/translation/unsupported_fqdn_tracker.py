"""
Tracker for unsupported FQDN domains during DCF translation.
"""

import logging
from collections import defaultdict
from dataclasses import asdict
from typing import Dict, List, Optional

import pandas as pd

from domain.constants import UnsupportedFQDNRecord


class UnsupportedFQDNTracker:
    """
    Centralized tracker for unsupported FQDN domains during DCF translation.
    
    This class collects and manages details about FQDN domains that are filtered
    out during the translation process, providing comprehensive reporting and
    analysis capabilities.
    """
    
    def __init__(self):
        """Initialize the tracker with empty collections."""
        self.records: List[UnsupportedFQDNRecord] = []
        self._logger = logging.getLogger(__name__)
    
    def add_record(self, record: UnsupportedFQDNRecord) -> None:
        """
        Add an unsupported FQDN record to the tracker.
        
        Args:
            record: The UnsupportedFQDNRecord to add
        """
        self.records.append(record)
        self._logger.debug(f"Added unsupported FQDN record: {record.domain} for {record.webgroup_name}")
    
    def add_invalid_domain(
        self,
        fqdn_tag_name: str,
        webgroup_name: str,
        domain: str,
        port: str,
        protocol: str,
        reason: str
    ) -> None:
        """
        Add an invalid domain record with individual parameters.
        
        Args:
            fqdn_tag_name: The name of the FQDN tag
            webgroup_name: The name of the webgroup
            domain: The invalid domain
            port: The port number
            protocol: The protocol (TCP/UDP)
            reason: The reason for rejection
        """
        record = UnsupportedFQDNRecord(
            fqdn_tag_name=fqdn_tag_name,
            webgroup_name=webgroup_name,
            domain=domain,
            port=port,
            protocol=protocol,
            reason=reason
        )
        self.add_record(record)
    
    def get_total_count(self) -> int:
        """Get the total number of unsupported domains."""
        return len(self.records)
    
    def get_affected_webgroups_count(self) -> int:
        """Get the number of unique webgroups affected by unsupported domains."""
        return len(set(record.webgroup_name for record in self.records))
    
    def get_affected_fqdn_tags_count(self) -> int:
        """Get the number of unique FQDN tags affected by unsupported domains."""
        return len(set(record.fqdn_tag_name for record in self.records))
    
    def get_summary_by_reason(self) -> Dict[str, int]:
        """
        Get a summary of unsupported domains grouped by rejection reason.
        
        Returns:
            Dictionary mapping reasons to counts
        """
        reason_counts = defaultdict(int)
        for record in self.records:
            reason_counts[record.reason] += 1
        return dict(reason_counts)
    
    def get_summary_by_webgroup(self) -> Dict[str, int]:
        """
        Get a summary of unsupported domains grouped by webgroup.
        
        Returns:
            Dictionary mapping webgroup names to counts
        """
        webgroup_counts = defaultdict(int)
        for record in self.records:
            webgroup_counts[record.webgroup_name] += 1
        return dict(webgroup_counts)
    
    def get_summary_by_fqdn_tag(self) -> Dict[str, int]:
        """
        Get a summary of unsupported domains grouped by FQDN tag.
        
        Returns:
            Dictionary mapping FQDN tag names to counts
        """
        tag_counts = defaultdict(int)
        for record in self.records:
            tag_counts[record.fqdn_tag_name] += 1
        return dict(tag_counts)
    
    def get_top_rejected_domains(self, limit: int = 10) -> List[Dict[str, int]]:
        """
        Get the most frequently rejected domains.
        
        Args:
            limit: Maximum number of domains to return
            
        Returns:
            List of dictionaries with domain and count
        """
        domain_counts = defaultdict(int)
        for record in self.records:
            domain_counts[record.domain] += 1
        
        sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"domain": domain, "count": count} for domain, count in sorted_domains[:limit]]
    
    def get_comprehensive_summary(self) -> Dict[str, any]:
        """
        Get a comprehensive summary of all unsupported FQDN statistics.
        
        Returns:
            Dictionary with detailed statistics
        """
        return {
            "total_count": self.get_total_count(),
            "affected_webgroups": self.get_affected_webgroups_count(),
            "affected_fqdn_tags": self.get_affected_fqdn_tags_count(),
            "by_reason": self.get_summary_by_reason(),
            "by_webgroup": self.get_summary_by_webgroup(),
            "by_fqdn_tag": self.get_summary_by_fqdn_tag(),
            "top_rejected_domains": self.get_top_rejected_domains(10)
        }
    
    def to_dataframe(self) -> pd.DataFrame:
        """
        Convert all records to a pandas DataFrame for CSV export.
        
        Returns:
            DataFrame with all unsupported FQDN records
        """
        if not self.records:
            # Return empty DataFrame with proper columns
            return pd.DataFrame(columns=[
                "fqdn_tag_name", "webgroup_name", "domain", "port", "protocol", "reason"
            ])
        
        return pd.DataFrame([asdict(record) for record in self.records])
    
    def log_summary(self, log_level: int = logging.INFO) -> None:
        """
        Log a comprehensive summary of unsupported domains.
        
        Args:
            log_level: The logging level to use
        """
        if not self.records:
            self._logger.log(log_level, "No unsupported FQDN domains found during translation")
            return
        
        summary = self.get_comprehensive_summary()
        
        self._logger.log(log_level, f"=== Unsupported FQDN Domains Summary ===")
        self._logger.log(log_level, f"Total unsupported domains: {summary['total_count']}")
        self._logger.log(log_level, f"Affected webgroups: {summary['affected_webgroups']}")
        self._logger.log(log_level, f"Affected FQDN tags: {summary['affected_fqdn_tags']}")
        
        self._logger.log(log_level, "Breakdown by reason:")
        for reason, count in summary['by_reason'].items():
            self._logger.log(log_level, f"  {reason}: {count} domains")
        
        self._logger.log(log_level, "Top 5 most affected webgroups:")
        sorted_webgroups = sorted(summary['by_webgroup'].items(), key=lambda x: x[1], reverse=True)
        for webgroup, count in sorted_webgroups[:5]:
            self._logger.log(log_level, f"  {webgroup}: {count} domains")
        
        self._logger.log(log_level, "Top 5 most rejected domains:")
        for domain_info in summary['top_rejected_domains'][:5]:
            self._logger.log(log_level, f"  {domain_info['domain']}: {domain_info['count']} occurrences")
        
        self._logger.log(log_level, "=== End Unsupported FQDN Summary ===")
    
    def clear(self) -> None:
        """Clear all records from the tracker."""
        self.records.clear()
        self._logger.debug("Cleared all unsupported FQDN records")