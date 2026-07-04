#!/usr/bin/env python3
"""
guidance.py — turns a CVE/news item into specific, actionable Tanium and
Rapid7 hints.

Design goals:
- Name the actual product / CVE / port pulled from the item, not "if a
  product is implicated."
- Use real Tanium sensor names and real InsightVM concepts so the hint is a
  usable starting point (the analyst still writes/finalizes the query).
- Reason about whether the target is even a Tanium-managed endpoint — a
  router, a browser extension, or a mobile app is NOT, and saying "look it
  up in Installed Applications" for those is wrong. Say so instead.
- Stay generic: names public products/CVEs from the item, never any
  organization's asset names or internal environment.
"""

import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# "port 8443", "8443/tcp", "tcp/8443"
PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b|\b(\d{2,5})/(?:tcp|udp)\b|\b(?:tcp|udp)/(\d{2,5})\b", re.I)

# Products/vendors worth recognizing, mapped to a clean display name.
# Order matters: more specific terms first.
KNOWN_PRODUCTS = [
    ("Fortinet FortiOS", ["fortios", "fortigate", "fortinet"]),
    ("Palo Alto PAN-OS", ["pan-os", "globalprotect", "palo alto"]),
    ("Cisco ASA/IOS", ["cisco asa", "cisco ios", "cisco"]),
    ("Citrix NetScaler ADC", ["netscaler", "citrix adc", "citrix"]),
    ("Ivanti Connect Secure", ["ivanti", "pulse secure", "connect secure"]),
    ("Microsoft Exchange", ["exchange server", "exchange", "outlook web"]),
    ("Microsoft SharePoint", ["sharepoint"]),
    ("Microsoft Windows", ["windows server", "windows"]),
    ("Google Chrome", ["chrome"]),
    ("Mozilla Firefox", ["firefox"]),
    ("Apache Log4j", ["log4j", "log4shell"]),
    ("Apache HTTP Server", ["apache http", "apache httpd", "httpd", "apache"]),
    ("VMware ESXi/vCenter", ["esxi", "vcenter", "vmware"]),
    ("Atlassian Confluence", ["confluence"]),
    ("Progress MOVEit Transfer", ["moveit"]),
    ("Fortra GoAnywhere MFT", ["goanywhere"]),
    ("SolarWinds Orion", ["solarwinds"]),
    ("OpenSSH", ["openssh"]),
    ("WordPress", ["wordpress"]),
    ("Adobe Acrobat/Reader", ["acrobat", "adobe reader"]),
    ("SAP NetWeaver", ["netweaver"]),
    ("Zimbra Collaboration", ["zimbra"]),
    ("Zoho ManageEngine", ["manageengine", "zoho"]),
    ("PaperCut", ["papercut"]),
]

# Words that signal the target is a network appliance / not a managed endpoint.
APPLIANCE_TERMS = [
    "router", "firewall", "vpn appliance", "gateway", "load balancer",
    "netscaler", "fortigate", "pan-os", "switch", "nas", "san",
    "ip camera", "printer", "iot",
]


def _find_product(text_lower: str) -> str | None:
    for name, terms in KNOWN_PRODUCTS:
        if any(term in text_lower for term in terms):
            return name
    return None


def _special_kind(text_lower: str) -> str | None:
    if "extension" in text_lower and any(b in text_lower for b in ("chrome", "browser", "edge", "firefox")):
        return "browser_extension"
    if any(k in text_lower for k in ("ios app", "android app", "mobile app", "app store", "google play", " ios ", " android ")):
        return "mobile_app"
    return None


def extract_targets(text: str, vendor: str | None = None, product: str | None = None) -> dict:
    """Pull product, CVE, ports, and shape flags from freeform text.
    If vendor/product are already known (CVE items), use them directly."""
    tl = (text or "").lower()

    if product and product.lower() not in ("unknown", ""):
        if vendor and vendor.lower() not in ("unknown", "") and vendor.lower() not in product.lower():
            display = f"{vendor} {product}".strip()
        else:
            display = product
    else:
        display = _find_product(tl)

    cve_match = CVE_RE.search(text or "")
    cve = cve_match.group(0).upper() if cve_match else None

    ports = []
    for pm in PORT_RE.finditer(text or ""):
        p = next((g for g in pm.groups() if g), None)
        if p and 1 <= int(p) <= 65535 and p not in ports:
            ports.append(p)

    is_appliance = any(term in tl for term in APPLIANCE_TERMS)
    if display and any(term in display.lower() for term in APPLIANCE_TERMS):
        is_appliance = True

    return {
        "product": display,
        "cve": cve,
        "ports": ports,
        "is_appliance": is_appliance,
        "special": _special_kind(tl),
    }


def tanium_hint(targets: dict) -> str:
    product = targets.get("product")
    ports = targets.get("ports") or []
    port_str = ", ".join(ports)
    special = targets.get("special")

    if special == "browser_extension":
        return (
            "Browser add-ons don't show up in the Installed Applications sensor. "
            "Use a Browser Extensions sensor (Tanium community sensor, or a custom "
            "one reading the Chrome/Edge Extensions path or registry) and filter by "
            "the extension ID to find affected machines."
        )
    if special == "mobile_app":
        return (
            "Tanium's endpoint inventory won't see iOS/Android app installs unless "
            "you run Tanium mobile. If you don't, treat this as awareness-only for "
            "endpoints and check for any desktop companion software of the named "
            "vendors via Installed Applications instead."
        )

    if targets.get("is_appliance"):
        base = (
            f"{product or 'This device'} is typically a network appliance, not a "
            "Tanium-managed endpoint. If it isn't under Tanium, pivot to the Open "
            "Ports sensor on adjacent managed hosts to spot exposed management "
            "interfaces"
        )
        if port_str:
            base += f" (e.g. {port_str})"
        base += ", and use your network/asset inventory to confirm firmware versions."
        return base

    if product:
        hint = (
            f'Use Installed Application Version["{product}"] to find affected builds '
            f'(or Installed Applications containing "{product}" for a broader sweep). '
            f'Question shape: Get Installed Application Version["{product}"] from all machines.'
        )
        if port_str:
            hint += f" Then cross-reference Open Ports for {port_str} on anything internet-facing."
        return hint

    # No product identified — still give a concrete path, not boilerplate.
    hint = (
        "No single product is named. Use Installed Applications to inventory the "
        "software class in the report, then the Open Ports sensor to surface exposed "
        "services worth prioritizing."
    )
    if port_str:
        hint += f" Start with endpoints exposing {port_str}."
    return hint


def rapid7_hint(targets: dict) -> str:
    product = targets.get("product")
    cve = targets.get("cve")
    special = targets.get("special")

    if special == "browser_extension":
        return (
            "InsightVM doesn't scan browser extensions. Instead, research the "
            "extension's callback/C2 domains from the report and confirm none resolve "
            "on internet-facing assets you scan; handle removal via MDM/EDR."
        )
    if special == "mobile_app":
        return (
            "InsightVM doesn't cover mobile apps — no direct scan action. Track "
            "affected apps through your MDM rather than the scanner."
        )

    if cve:
        hint = (
            f"In InsightVM, filter the vulnerability view by {cve}. If the check only "
            "returns a version/potential match, run a credentialed scan to confirm real "
            "exposure. "
        )
        hint += (
            f'Build a dynamic asset group on installed "{product}" to track remediation.'
            if product else
            "Build a dynamic asset group on the affected software to track remediation."
        )
        return hint

    if product:
        return (
            f'In InsightVM, search vulnerabilities for "{product}" and confirm your active '
            "scan template covers it (use a credentialed full audit, not a discovery scan). "
            f'Create a dynamic asset group on installed "{product}" for remediation tracking.'
        )

    return (
        "In InsightVM, find the vulnerability check matching the software in this report, "
        "confirm it's in your active scan template, and prefer a credentialed scan for "
        "reliable confirmation over a version-only match."
    )


def build_hints(text: str, vendor: str | None = None, product: str | None = None) -> dict:
    targets = extract_targets(text, vendor=vendor, product=product)
    return {"tanium_hint": tanium_hint(targets), "rapid7_hint": rapid7_hint(targets)}
