"""
Unit tests for CIDRAnalyzer.generate_internet_cidr_exclusions.

Asserts the custom Internet SmartGroup matches the Aviatrix
"Public Internet" SmartGroup (avtx_system_internet_routes_app_domain) baseline:
0.0.0.0/0 minus RFC1918 + CGNAT, further reduced by non-RFC1918/CGNAT VPC CIDRs.
"""

import ipaddress

import pandas as pd
import pytest

from src.analysis.cidr_analyzer import CIDRAnalyzer


PUBLIC_INTERNET_38 = [
    "0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4",
    "32.0.0.0/3", "64.0.0.0/3", "96.0.0.0/6", "100.0.0.0/10",
    "100.128.0.0/9", "101.0.0.0/8", "102.0.0.0/7", "104.0.0.0/5",
    "112.0.0.0/4", "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6",
    "172.0.0.0/12", "172.32.0.0/11", "172.64.0.0/10", "172.128.0.0/9",
    "173.0.0.0/8", "174.0.0.0/7", "176.0.0.0/4", "192.0.0.0/9",
    "192.128.0.0/11", "192.160.0.0/13", "192.169.0.0/16",
    "192.170.0.0/15", "192.172.0.0/14", "192.176.0.0/12",
    "192.192.0.0/10", "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6",
    "200.0.0.0/5", "208.0.0.0/4", "224.0.0.0/3",
]


def _covers(networks, addr):
    ip = ipaddress.IPv4Address(addr)
    return any(ip in ipaddress.IPv4Network(n) for n in networks)


class TestGenerateInternetCidrExclusions:
    def setup_method(self):
        self.analyzer = CIDRAnalyzer()

    def test_no_vpc_cidrs_matches_public_internet_baseline(self):
        result = self.analyzer.generate_internet_cidr_exclusions([])
        assert sorted(result) == sorted(PUBLIC_INTERNET_38)

    def test_rfc1918_vpc_cidr_does_not_alter_baseline(self):
        # An RFC1918 VPC CIDR is already excluded by the baseline.
        result = self.analyzer.generate_internet_cidr_exclusions(["10.5.0.0/16"])
        assert sorted(result) == sorted(PUBLIC_INTERNET_38)

    def test_cgnat_vpc_cidr_does_not_alter_baseline(self):
        result = self.analyzer.generate_internet_cidr_exclusions(["100.64.5.0/24"])
        assert sorted(result) == sorted(PUBLIC_INTERNET_38)

    def test_non_rfc1918_vpc_cidr_is_excluded(self):
        result = self.analyzer.generate_internet_cidr_exclusions(["40.0.0.0/16"])
        # The VPC CIDR must not be covered by any returned network.
        assert not _covers(result, "40.0.0.5")
        # A neighbor inside the original /8 supernet must still be covered.
        assert _covers(result, "40.1.0.5")
        # RFC1918/CGNAT addresses must remain excluded.
        assert not _covers(result, "10.0.0.1")
        assert not _covers(result, "172.16.0.1")
        assert not _covers(result, "192.168.0.1")
        assert not _covers(result, "100.64.0.1")

    def test_mixed_rfc1918_and_non_rfc1918(self):
        result = self.analyzer.generate_internet_cidr_exclusions([
            "10.5.0.0/16",       # RFC1918 - ignored
            "40.0.0.0/16",       # public - subtracted
        ])
        assert not _covers(result, "40.0.0.5")
        assert not _covers(result, "10.5.0.1")     # baseline still excludes RFC1918
        assert _covers(result, "40.1.0.5")

    def test_invalid_cidr_is_skipped(self):
        result = self.analyzer.generate_internet_cidr_exclusions(["not-a-cidr", "40.0.0.0/16"])
        assert not _covers(result, "40.0.0.5")
        # Baseline remains intact aside from the one valid public CIDR carve-out.
        assert _covers(result, "8.8.8.8")

    def test_analyze_vpc_cidr_requirements_uses_new_baseline(self):
        df = pd.DataFrame([
            {"vpc_cidr": "40.0.0.0/16"},
            {"vpc_cidr": "10.0.0.0/16"},
        ])
        result = self.analyzer.analyze_vpc_cidr_requirements(df)
        assert result["requires_custom_internet_smartgroup"] is True
        exclusions = result["internet_cidr_exclusions"]
        assert not _covers(exclusions, "40.0.0.5")
        assert not _covers(exclusions, "10.0.0.1")
        assert not _covers(exclusions, "192.168.0.1")
