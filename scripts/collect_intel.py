#!/usr/bin/env python3
"""
collect_intel.py — VulnWire intelligence collector

Pulls known-exploited vulnerabilities from CISA KEV, optionally enriches
each entry with CVSS data from NVD, applies a transparent priority score
and generic vulnerability-class tags, and (optionally) asks an LLM for a
plain-language executive summary. Writes the result to data/intel.json.

Scope / guardrails (intentional):
- This pipeline is 100% generic and public-source. It never references
  any specific organization's assets, hostnames, or environment.
- If AI enrichment is enabled, the prompt explicitly forbids inventing
  asset names, hostnames, or org-specific detail.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

import enrich
import guidance

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

OUTPUT_PATH = Path("data/intel.json")
SCHEMA_VERSION = "1.1"

MAX_ITEMS = int(os.environ.get("VULNWIRE_MAX_ITEMS", "25"))
NVD_API_KEY = os.environ.get("NVD_API_KEY")            # optional, raises NVD rate limit

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vulnwire")

TAG_KEYWORDS = {
    "network edge": ["router", "firewall", "vpn", "gateway", "edge", "load balancer"],
    "unauthenticated rce": ["remote code execution", "rce", "unauthenticated"],
    "privilege escalation": ["privilege escalation", "elevation of privilege", "local privilege"],
    "identity": ["active directory", "identity", "sso", "authentication", "okta", "ldap", "kerberos"],
    "web application": ["web application", "cms", "wordpress", "sql injection", "cross-site", "xss"],
    "denial of service": ["denial of service", "dos "],
    "cloud": ["cloud", "aws", "azure", "gcp", "kubernetes", "container"],
    "endpoint": ["windows", "macos", "endpoint", "workstation"],
}


def fetch_kev(max_items: int) -> list[dict]:
    log.info("Fetching CISA KEV catalog...")
    resp = requests.get(CISA_KEV_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    # Most recently added first
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    log.info("Fetched %d KEV entries, using most recent %d", len(vulns), min(max_items, len(vulns)))
    return vulns[:max_items]


def fetch_nvd_details(cve_id: str) -> dict | None:
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {"cveId": cve_id}
    try:
        resp = requests.get(NVD_CVE_URL, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
        vulns = payload.get("vulnerabilities", [])
        if not vulns:
            return None
        return vulns[0].get("cve", {})
    except requests.RequestException as exc:
        log.warning("NVD lookup failed for %s: %s", cve_id, exc)
        return None
    finally:
        # Be polite to the public API even with a key.
        time.sleep(0.6 if NVD_API_KEY else 6.0)


def extract_cvss(nvd_cve: dict | None) -> dict:
    if not nvd_cve:
        return {"cvss_v3_score": None, "cvss_v3_vector": None, "rating": "Unknown"}
    metrics = nvd_cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            entry = metrics[key][0]
            cvss_data = entry.get("cvssData", {})
            return {
                "cvss_v3_score": cvss_data.get("baseScore"),
                "cvss_v3_vector": cvss_data.get("vectorString"),
                "rating": cvss_data.get("baseSeverity", "Unknown").title(),
            }
    return {"cvss_v3_score": None, "cvss_v3_vector": None, "rating": "Unknown"}


def classify_tags(text: str) -> list[str]:
    text_lower = text.lower()
    tags = [tag for tag, keywords in TAG_KEYWORDS.items() if any(kw in text_lower for kw in keywords)]
    return tags or ["general"]


def build_item(kev_entry: dict, epss_map: dict) -> dict:
    cve_id = kev_entry.get("cveID", "UNKNOWN")
    vendor = kev_entry.get("vendorProject", "Unknown")
    product = kev_entry.get("product", "Unknown")
    description = kev_entry.get("shortDescription", "")

    log.info("Processing %s (%s %s)", cve_id, vendor, product)

    nvd_cve = fetch_nvd_details(cve_id)
    cvss = extract_cvss(nvd_cve)
    tags = classify_tags(f"{description} {vendor} {product}")
    epss_entry = epss_map.get(cve_id, {})
    epss_score = epss_entry.get("score")
    priority = enrich.unified_priority(
        kev=True,
        ransomware=kev_entry.get("knownRansomwareCampaignUse", "Unknown") == "Known",
        cvss=cvss["cvss_v3_score"],
        epss=epss_score,
    )
    )
    badges = enrich.extract_badges(
        f"{kev_entry.get('vulnerabilityName','')}. {description}",
        kev=True, nvd_cvss=cvss["cvss_v3_score"], nvd_rating=cvss["rating"],
    )
    badges["epss_score"] = epss_score
    badges["priority_label"] = priority["priority_label"]
    targets = guidance.extract_targets(description, vendor=vendor, product=product)
    impact = enrich.extract_impact(description, targets.get("product"),
                                   targets.get("is_appliance", False), targets.get("special"))

    return {
        "cve_id": cve_id,
        "title": kev_entry.get("vulnerabilityName", cve_id),
        "vendor": vendor,
        "product": product,
        "description": description,
        "date_added_to_kev": kev_entry.get("dateAdded"),
        "action_due_date": kev_entry.get("dueDate"),
        "severity": cvss,
        "exploitation": {
            "is_kev": True,
            "known_ransomware_use": kev_entry.get("knownRansomwareCampaignUse", "Unknown") == "Known",
        },
        "priority": priority,
        "vulnerability_class_tags": tags,
        },
        "badges": badges,
        "impact": impact,
        "sources": [
            {"name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
            {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
        ],
    }


def main() -> None:
    kev_entries = fetch_kev(MAX_ITEMS)
    # Batch-fetch EPSS for all CVEs up front (free FIRST.org API, no key).
    epss_map = enrich.fetch_epss([e.get("cveID", "") for e in kev_entries if e.get("cveID")])
    log.info("EPSS scores retrieved for %d/%d CVEs", len(epss_map), len(kev_entries))
    items = [build_item(entry, epss_map) for entry in kev_entries]
    items.sort(key=lambda i: i["priority"]["priority_score"], reverse=True)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "item_count": len(items),
        "items": items,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2))
    log.info("Wrote %d items to %s", len(items), OUTPUT_PATH)


if __name__ == "__main__":
    main()
