#!/usr/bin/env python3
"""
guidance.py — extracts product/CVE/port targets from item text.

Design goals:
- Name the actual product / CVE / port pulled from the item, not "if a
  product is implicated."
- Stay generic: names public products/CVEs from the item only.
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


