"""Tests for shared IOC extraction."""

from vhir_cli.commands.report import _extract_all_iocs
from vhir_cli.iocs import extract_iocs_from_findings


def test_report_and_review_extract_the_same_iocs():
    """`vhir report --ioc` must not drift from `vhir review --iocs`."""
    findings = [
        {
            "iocs": {"IPv4": ["192.168.1.50"], "Domain": ["evil.example.com"]},
            "observation": "PsExec ran from 10.20.30.40",
            "interpretation": r"Dropped C:\Windows\Temp\evil.exe",
        },
        {
            "iocs": [{"type": "IPv4", "value": "5.6.7.8"}],
            "observation": f"Hash: {'a' * 64}",
            "interpretation": "Beaconed to bad.example.org",
        },
    ]

    review_iocs = extract_iocs_from_findings(findings)
    report_iocs = _extract_all_iocs(findings)

    assert report_iocs == {k: sorted(v) for k, v in sorted(review_iocs.items())}
