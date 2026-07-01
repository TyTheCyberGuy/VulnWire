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
- "query_guidance" fields are best-practice PATTERNS for how someone
  might approach a Tanium/Rapid7 query for this class of vulnerability —
  never a literal, ready-to-run query. The analyst types their own
  queries by hand.
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

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

OUTPUT_PATH = Path("data/intel.json")
SCHEMA_VERSION = "1.1"

MAX_ITEMS = int(os.environ.get("VULNWIRE_MAX_ITEMS", "25"))
NVD_API_KEY = os.environ.get("NVD_API_KEY")            # optional, raises NVD rate limit
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")      # optional
ENABLE_AI = os.environ.get("VULNWIRE_ENABLE_AI", "false").lower() == "true"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vulnwire")

# ---------------------------------------------------------------------------
# Generic best-practice query guidance, keyed by vulnerability class tag.
# These are patterns/approaches, not literal query strings — deliberately
# generic so nothing environment-specific ever leaks into the output.
# ---------------------------------------------------------------------------
QUERY_GUIDANCE_LIBRARY = {
    "network edge": {
        "tanium_pattern": "Target by installed application name/version matching the affected product, combined with an OS platform filter. For appliances/firmware, target by device banner or management-interface fingerprint if your sensor supports it.",
        "rapid7_pattern": "Filter scan results by CVE ID or the vendor advisory's associated Rapid7 vulnerability check ID; confirm exposure on the specific service port called out in the advisory.",
    },
    "unauthenticated rce": {
        "tanium_pattern": "Query for installed application/version below the fixed release, then cross-reference with network exposure sensors (listening ports, external reachability) since unauthenticated RCE severity depends heavily on reachability.",
        "rapid7_pattern": "Prioritize scan results where the check confirms remote exploitability (not just version match) — many RCE checks include an active-verification variant, use it when available.",
    },
    "privilege escalation": {
        "tanium_pattern": "Target by installed application/kernel/package version. Combine with a check for local user accounts or service accounts, since impact depends on existing local access.",
        "rapid7_pattern": "Use a credentialed scan; privilege-escalation checks are typically far less reliable (or entirely unavailable) via unauthenticated scanning.",
    },
    "identity": {
        "tanium_pattern": "Target affected identity/SSO/directory service software by version. Consider pairing with a check for exposed authentication endpoints.",
        "rapid7_pattern": "Confirm whether the check requires authenticated access to the IdP; many identity CVEs need credentialed or API-based validation rather than a network scan.",
    },
    "web application": {
        "tanium_pattern": "Target by installed web server/application framework version and by presence of the affected component (plugin, module, library).",
        "rapid7_pattern": "Use the web application scan template rather than a general network template; confirm the affected path/endpoint is reachable.",
    },
    "denial of service": {
        "tanium_pattern": "Target by installed application/version. DoS conditions are rarely worth an active-exploitation check — version confirmation is usually sufficient for triage.",
        "rapid7_pattern": "Standard version-based check is typically adequate; active verification for DoS is often skipped to avoid causing an outage during scanning.",
    },
    "default": {
        "tanium_pattern": "Target by installed application/version matching the affected product and platform, then cross-reference with network exposure where relevant.",
        "rapid7_pattern": "Filter by CVE ID or vendor advisory check ID and confirm the check type (version-based vs. active verification) matches your risk tolerance for scanning.",
    },
}

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


def query_guidance_for_tags(tags: list[str]) -> dict:
    for tag in tags:
        if tag in QUERY_GUIDANCE_LIBRARY:
            return QUERY_GUIDANCE_LIBRARY[tag]
    return QUERY_GUIDANCE_LIBRARY["default"]


def score_priority(kev_entry: dict, cvss_score: float | None) -> dict:
    score = 40  # baseline: presence in KEV already means confirmed exploitation
    reasons = ["Listed in CISA's Known Exploited Vulnerabilities catalog."]

    if kev_entry.get("knownRansomwareCampaignUse", "Unknown") == "Known":
        score += 30
        reasons.append("Associated with known ransomware campaign use.")

    if cvss_score is not None:
        if cvss_score >= 9.0:
            score += 25
        elif cvss_score >= 7.0:
            score += 15
        elif cvss_score >= 4.0:
            score += 5
        reasons.append(f"CVSS v3 base score: {cvss_score}.")
    else:
        reasons.append("CVSS score unavailable from NVD at collection time.")

    score = min(score, 100)

    if score >= 85:
        rec = "Escalate today"
    elif score >= 60:
        rec = "Investigate today"
    elif score >= 35:
        rec = "Monitor"
    else:
        rec = "Can wait"

    return {"priority_score": score, "triage_recommendation": rec, "reason": " ".join(reasons)}


def ai_enrich(cve_id: str, description: str) -> dict:
    """Optional LLM enrichment. Explicitly forbidden from inventing
    environment-specific detail. Fails soft (returns None-filled dict)
    if no key is configured or the call fails."""
    if not (ENABLE_AI and OPENAI_API_KEY):
        return {"executive_summary": None, "analyst_notes": None}

    prompt = (
        "You are a vulnerability management analyst assistant. Given the CVE "
        f"ID {cve_id} and description below, return STRICT JSON only, no "
        "markdown, no commentary, with exactly two keys: "
        '"executive_summary" (one plain-language sentence on what the '
        'vulnerability is and why it matters) and "analyst_notes" (1-2 '
        "sentences of general triage guidance). Do NOT invent or reference "
        "any specific organization's asset names, hostnames, internal tools, "
        "or environment details. Keep it fully generic and applicable to any "
        f"organization.\n\nDescription: {description}"
    )
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
                "temperature": 0.2,
            },
            timeout=30,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        return {
            "executive_summary": parsed.get("executive_summary"),
            "analyst_notes": parsed.get("analyst_notes"),
        }
    except (requests.RequestException, KeyError, json.JSONDecodeError) as exc:
        log.warning("AI enrichment failed for %s: %s", cve_id, exc)
        return {"executive_summary": None, "analyst_notes": None}


def build_item(kev_entry: dict) -> dict:
    cve_id = kev_entry.get("cveID", "UNKNOWN")
    vendor = kev_entry.get("vendorProject", "Unknown")
    product = kev_entry.get("product", "Unknown")
    description = kev_entry.get("shortDescription", "")

    log.info("Processing %s (%s %s)", cve_id, vendor, product)

    nvd_cve = fetch_nvd_details(cve_id)
    cvss = extract_cvss(nvd_cve)
    tags = classify_tags(f"{description} {vendor} {product}")
    priority = score_priority(kev_entry, cvss["cvss_v3_score"])
    guidance = query_guidance_for_tags(tags)
    enrichment = ai_enrich(cve_id, description)

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
        "query_guidance": guidance,
        "ai_enrichment": enrichment,
        "sources": [
            {"name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
            {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
        ],
    }


def main() -> None:
    kev_entries = fetch_kev(MAX_ITEMS)
    items = [build_item(entry) for entry in kev_entries]
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
