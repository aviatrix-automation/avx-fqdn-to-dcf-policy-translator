"""
Internet SmartGroup Resolver for Dynamic SmartGroup ID Management

This module provides functionality to dynamically determine which Internet SmartGroup ID
to use based on VPC CIDR analysis and custom Internet SmartGroup requirements.
"""

import logging
from typing import Dict, Any, Optional

import pandas as pd
from analysis.cidr_analyzer import CIDRAnalyzer


class InternetSmartGroupResolver:
    """Resolves Internet SmartGroup IDs based on VPC CIDR analysis."""

    def __init__(self, default_internet_sg_id: str, custom_internet_sg_name: str = "Internet_Custom"):
        """
        Initialize the Internet SmartGroup resolver.
        
        Args:
            default_internet_sg_id: Default Internet SmartGroup ID (UUID)
            custom_internet_sg_name: Name for custom Internet SmartGroup
        """
        self.default_internet_sg_id = default_internet_sg_id
        self.custom_internet_sg_name = custom_internet_sg_name
        self.cidr_analyzer = CIDRAnalyzer()
        self.logger = logging.getLogger(__name__)
        
        # Cache analysis results to avoid repeated calculations
        self._analysis_cache: Optional[Dict[str, Any]] = None

    def get_internet_smartgroup_id(self, gateways_df: pd.DataFrame) -> str:
        """
        Return appropriate Internet SmartGroup ID based on VPC analysis.
        
        Args:
            gateways_df: DataFrame containing gateway configuration data
            
        Returns:
            Either default Internet SmartGroup ID or custom SmartGroup reference
        """
        if self._needs_custom_internet_smartgroup(gateways_df):
            custom_sg_reference = f"${{aviatrix_smart_group.{self.custom_internet_sg_name}.id}}"
            self.logger.info(f"Using custom Internet SmartGroup: {custom_sg_reference}")
            return custom_sg_reference
        else:
            self.logger.info(f"Using default Internet SmartGroup: {self.default_internet_sg_id}")
            return self.default_internet_sg_id

    def _needs_custom_internet_smartgroup(self, gateways_df: pd.DataFrame) -> bool:
        """
        Determine if custom Internet SmartGroup is needed.
        
        Args:
            gateways_df: DataFrame containing gateway configuration data
            
        Returns:
            True if custom Internet SmartGroup is required
        """
        # Use cached analysis if available
        if self._analysis_cache is None:
            self._analysis_cache = self.cidr_analyzer.analyze_vpc_cidr_requirements(gateways_df)
            
        return self._analysis_cache.get('requires_custom_internet_smartgroup', False)

    def get_analysis_results(self, gateways_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Get comprehensive VPC CIDR analysis results.
        
        Args:
            gateways_df: DataFrame containing gateway configuration data
            
        Returns:
            Dictionary containing analysis results
        """
        if self._analysis_cache is None:
            self._analysis_cache = self.cidr_analyzer.analyze_vpc_cidr_requirements(gateways_df)
            
        return self._analysis_cache.copy()

    def should_create_custom_smartgroup(self, gateways_df: pd.DataFrame) -> bool:
        """
        Check if custom Internet SmartGroup should be created.
        
        This is an alias for _needs_custom_internet_smartgroup for external use.
        
        Args:
            gateways_df: DataFrame containing gateway configuration data
            
        Returns:
            True if custom Internet SmartGroup should be created
        """
        return self._needs_custom_internet_smartgroup(gateways_df)

    def get_custom_smartgroup_definition(self, gateways_df: pd.DataFrame) -> Optional[Dict[str, Any]]:
        """
        Generate custom Internet SmartGroup definition if required.
        
        Args:
            gateways_df: DataFrame containing gateway configuration data
            
        Returns:
            SmartGroup definition dictionary or None if not needed
        """
        if not self._needs_custom_internet_smartgroup(gateways_df):
            return None

        analysis = self.get_analysis_results(gateways_df)
        internet_cidrs = analysis.get('internet_cidr_exclusions', [])
        
        if not internet_cidrs:
            self.logger.warning("Custom Internet SmartGroup needed but no Internet CIDRs generated")
            return None

        # Create match expressions for all Internet CIDRs
        match_expressions = []
        for cidr in internet_cidrs:
            match_expressions.append({"cidr": cidr})

        smartgroup_def = {
            "name": self.custom_internet_sg_name,
            "selector": {
                "match_expressions": match_expressions
            },
            "source_type": "custom_internet",
            "vpc_cidrs": analysis.get('vpc_cidrs', []),
            "non_standard_cidrs": analysis.get('non_standard_cidrs', []),
            "description": f"Custom Internet SmartGroup excluding VPC CIDRs: {', '.join(analysis.get('non_standard_cidrs', []))}"
        }

        self.logger.info(
            f"Generated custom Internet SmartGroup definition with {len(match_expressions)} CIDR expressions"
        )
        
        return smartgroup_def

    def clear_cache(self):
        """Clear the analysis cache to force re-analysis."""
        self._analysis_cache = None

    def get_summary_info(self, gateways_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Get summary information about Internet SmartGroup requirements.
        
        Args:
            gateways_df: DataFrame containing gateway configuration data
            
        Returns:
            Summary information dictionary
        """
        analysis = self.get_analysis_results(gateways_df)
        internet_sg_id = self.get_internet_smartgroup_id(gateways_df)
        
        summary = {
            'internet_smartgroup_id': internet_sg_id,
            'uses_custom_smartgroup': self._needs_custom_internet_smartgroup(gateways_df),
            'total_vpc_cidrs': analysis.get('total_vpc_cidrs', 0),
            'non_standard_cidrs': analysis.get('non_standard_cidrs', []),
            'custom_smartgroup_name': self.custom_internet_sg_name if self._needs_custom_internet_smartgroup(gateways_df) else None,
            'internet_cidr_count': len(analysis.get('internet_cidr_exclusions', []))
        }
        
        return summary

    def log_analysis_summary(self, gateways_df: pd.DataFrame):
        """
        Log a summary of the VPC CIDR analysis and Internet SmartGroup decisions.
        
        Args:
            gateways_df: DataFrame containing gateway configuration data
        """
        summary = self.get_summary_info(gateways_df)
        analysis = self.get_analysis_results(gateways_df)
        
        self.logger.info("=== Internet SmartGroup Analysis Summary ===")
        self.logger.info(f"Total VPC CIDRs analyzed: {summary['total_vpc_cidrs']}")
        
        if analysis.get('rfc1918_cidrs'):
            self.logger.info(f"RFC1918 CIDRs: {analysis['rfc1918_cidrs']}")
        if analysis.get('cgnat_cidrs'):
            self.logger.info(f"CGNAT CIDRs: {analysis['cgnat_cidrs']}")
        if summary['non_standard_cidrs']:
            self.logger.info(f"Non-standard CIDRs: {summary['non_standard_cidrs']}")
            
        if summary['uses_custom_smartgroup']:
            self.logger.info(f"✓ Custom Internet SmartGroup required: {summary['custom_smartgroup_name']}")
            self.logger.info(f"  Internet CIDR exclusions: {summary['internet_cidr_count']} ranges")
            self.logger.info(f"  SmartGroup ID: {summary['internet_smartgroup_id']}")
        else:
            self.logger.info("✓ Standard Internet SmartGroup sufficient")
            self.logger.info(f"  SmartGroup ID: {summary['internet_smartgroup_id']}")
            
        self.logger.info("=== End Analysis Summary ===")
