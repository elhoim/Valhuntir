"""Shared IOC extraction for CLI commands.

Findings carry IOCs both in a structured `iocs` field and as free text in
`observation` / `interpretation`; review and report must extract the same set.
"""

from __future__ import annotations

import re


def extract_iocs_from_findings(findings: list[dict]) -> dict[str, set[str]]:
    """Extract IOCs from a list of findings."""
    collected: dict[str, set[str]] = {}

    for f in findings:
        iocs_field = f.get("iocs")
        if isinstance(iocs_field, dict):
            for ioc_type, values in iocs_field.items():
                if ioc_type not in collected:
                    collected[ioc_type] = set()
                if isinstance(values, list):
                    collected[ioc_type].update(str(v) for v in values)
                else:
                    collected[ioc_type].add(str(values))
        elif isinstance(iocs_field, list):
            for ioc in iocs_field:
                if isinstance(ioc, dict):
                    ioc_type = ioc.get("type", "Unknown")
                    ioc_value = ioc.get("value", "")
                    if ioc_type not in collected:
                        collected[ioc_type] = set()
                    collected[ioc_type].add(str(ioc_value))

        text = f"{f.get('observation', '')} {f.get('interpretation', '')}"
        extract_text_iocs(text, collected)

    return collected


def extract_text_iocs(text: str, collected: dict[str, set[str]]) -> None:
    """Extract common IOC patterns from free text."""
    ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    for ip in re.findall(ipv4_pattern, text):
        if not ip.startswith(("0.", "127.", "255.")):
            collected.setdefault("IPv4", set()).add(ip)

    for h in re.findall(r"\b[a-fA-F0-9]{64}\b", text):
        collected.setdefault("SHA256", set()).add(h.lower())

    for h in re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])", text):
        collected.setdefault("SHA1", set()).add(h.lower())

    for h in re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])", text):
        collected.setdefault("MD5", set()).add(h.lower())

    for fp in re.findall(r"[A-Z]:\\(?:[^\s,;]+)", text):
        collected.setdefault("File", set()).add(fp)

    for d in re.findall(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|cc|tk)\b", text
    ):
        collected.setdefault("Domain", set()).add(d.lower())
