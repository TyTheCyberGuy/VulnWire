#!/usr/bin/env python3
"""
enrich.py — free (no-API) analysis synthesis + badge/impact extraction.

Fully replaces any paid LLM enrichment. Strategy:
1. Try to fetch the full article HTML (RSS summaries are often truncated)
   and extract paragraph text. Falls back to the RSS summary on any failure.
2. Build the ANALYSIS from the article's lead sentence plus the most
   fact-dense sentences (counts of affected users/records, CVE IDs,
   version numbers, exploitation status), keeping original order.
3. Extract badges: active-exploitation flag, CVSS score/rating mentioned
   in the text, and a priority label derived from both.
4. Extract IMPACT & SCOPE: affected versions (or an honest "not provided,
   assume all until vendor clarifies") and a product-aware "how to
   determine impact" check.

Everything is deterministic and public-source. No API keys, no cost.
"""

import html
import re

import requests

UA = {"User-Agent": "Mozilla/5.0 (compatible; VulnWireBot/1.0; +https://github.com)"}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CVSS_RE = re.compile(r"CVSS(?:\s*v?3(?:\.\d)?)?\s*(?:score|base score)?\s*(?:of|:)?\s*(\d{1,2}\.\d)", re.I)
VERSION_RE = re.compile(
    r"(?:versions?\s+(?:prior to|before|up to|through|below)\s+[\w.\-]+"
    r"|versions?\s+[\w.\-]+\s+(?:and|or)\s+(?:earlier|below|prior)"
    r"|[\w.\-]+\s+(?:and|or)\s+earlier(?:\s+versions?)?"
    r"|versions?\s+[\d][\w.\-]*(?:\s*(?:to|through|-)\s*[\d][\w.\-]*)?)",
    re.I,
)
SENT_SPLIT = re.compile(r"(?<=[.!?])\s+")

EXPLOITED_TERMS = [
    "actively exploited", "active exploitation", "exploitation attempts",
    "under attack", "ongoing attacks", "exploited in the wild",
    "known exploited", "being exploited", "exploitation observed",
    "actively targeting", "actively abused",
]

FACT_TERMS = [
    "million", "thousand", "records", "individuals", "customers", "users",
    "affected", "impacted", "exposed", "stolen", "compromised", "breach",
    "exploit", "vulnerability", "attack", "ransom", "patch", "zero-day",
]


def _strip_html(raw: str) -> str:
    no_script = re.sub(r"<(script|style|nav|header|footer|aside)[^>]*>.*?</\1>", " ", raw, flags=re.S | re.I)
    no_tags = re.sub(r"<[^>]+>", " ", no_script)
    return re.sub(r"\s+", " ", html.unescape(no_tags)).strip()


def fetch_article_text(url: str, max_paragraphs: int = 8) -> str | None:
    """Best-effort full-text fetch. Returns None on any failure so the
    caller falls back to the RSS summary."""
    try:
        resp = requests.get(url, headers=UA, timeout=12)
        resp.raise_for_status()
        # Grab paragraph blocks; article lead paragraphs come first.
        paras = re.findall(r"<p[^>]*>(.*?)</p>", resp.text, flags=re.S | re.I)
        cleaned = []
        for p in paras:
            text = _strip_html(p)
            # Skip boilerplate-ish short fragments and cookie/subscribe junk.
            if len(text) < 60:
                continue
            low = text.lower()
            if any(junk in low for junk in ("cookie", "subscribe", "newsletter", "sign up", "advertis", "all rights reserved")):
                continue
            cleaned.append(text)
            if len(cleaned) >= max_paragraphs:
                break
        joined = " ".join(cleaned)
        return joined if len(joined) > 120 else None
    except requests.RequestException:
        return None


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in SENT_SPLIT.split(text or "") if len(s.strip()) > 25]


def _score_sentence(s: str) -> int:
    low = s.lower()
    score = 0
    if re.search(r"\d", s):
        score += 2  # numbers = facts
    if re.search(r"\d[\d,.]*\s*(million|thousand|billion)", low):
        score += 4  # affected-count style facts
    if CVE_RE.search(s):
        score += 3
    if any(t in low for t in EXPLOITED_TERMS):
        score += 3
    score += sum(1 for t in FACT_TERMS if t in low)
    return score


def synthesize_analysis(title: str, rss_summary: str, article_text: str | None, max_sentences: int = 3) -> str:
    """Lead sentence + highest-fact sentences, original order, <= max_sentences."""
    source = article_text or rss_summary or title
    sents = _sentences(source)
    if not sents:
        return rss_summary or title

    lead = sents[0]
    rest = sents[1:12]  # only consider the early article body
    ranked = sorted(((s, _score_sentence(s)) for s in rest), key=lambda x: x[1], reverse=True)
    picked = {lead}
    for s, sc in ranked:
        if len(picked) >= max_sentences:
            break
        if sc >= 1:
            picked.add(s)
    # Preserve original order
    ordered = [s for s in sents if s in picked][:max_sentences]
    return " ".join(ordered)


def extract_badges(text: str, kev: bool = False, nvd_cvss: float | None = None, nvd_rating: str | None = None) -> dict:
    low = (text or "").lower()
    active = kev or any(t in low for t in EXPLOITED_TERMS)

    cvss = nvd_cvss
    rating = nvd_rating
    if cvss is None:
        m = CVSS_RE.search(text or "")
        if m:
            try:
                cvss = float(m.group(1))
            except ValueError:
                cvss = None
    if cvss is not None and not rating:
        rating = "Critical" if cvss >= 9.0 else "High" if cvss >= 7.0 else "Medium" if cvss >= 4.0 else "Low"

    if active and (cvss is None or cvss >= 9.0):
        priority = "Emergency out-of-band"
    elif active or (cvss is not None and cvss >= 9.0):
        priority = "Patch within 48h"
    elif cvss is not None and cvss >= 7.0:
        priority = "Expedited cycle"
    else:
        priority = None  # plain news — no patch priority implied

    return {
        "active_exploitation": active,
        "cvss_score": cvss,
        "cvss_rating": rating,
        "priority_label": priority,
    }


def extract_impact(text: str, product: str | None, is_appliance: bool, special: str | None) -> dict:
    """Affected versions + a 'how to determine impact' check."""
    m = VERSION_RE.search(text or "")
    if m:
        affected = m.group(0).strip().rstrip(".,;")
        affected = affected[0].upper() + affected[1:]
    elif product:
        affected = f"{product} (specific versions not provided, assume all vulnerable until vendor clarifies)"
    else:
        affected = "Not specified in source reporting."

    if special == "browser_extension":
        how = "Inventory browser extensions across the fleet by extension ID; remove matches and review browsing/credential exposure for affected users."
    elif special == "mobile_app":
        how = "Check MDM inventory for the named apps; review any linked accounts or API keys for exposure."
    elif is_appliance and product:
        how = (f"Identify all internet-facing {product} devices. Check firmware versions against the advisory, "
               f"and review access logs for unauthorized access, unusual processes, or configuration changes.")
    elif product:
        how = (f"Inventory all {product} installations and compare versions against the advisory. "
               f"Review logs on matching hosts for unusual authentication or administrative actions.")
    else:
        how = "Identify systems running the software class described in the report and review vendor advisories for applicability."

    return {"affected_versions": affected, "how_to_check": how}


def extract_cves(text: str) -> list[str]:
    seen, out = set(), []
    for m in CVE_RE.finditer(text or ""):
        c = m.group(0).upper()
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


# ---------------------------------------------------------------------------
# EPSS — Exploit Prediction Scoring System (FIRST.org). Free, no API key.
# Returns probability (0-1) that a CVE will be exploited in the next 30 days.
# ---------------------------------------------------------------------------
EPSS_URL = "https://api.first.org/data/v1/epss"


def fetch_epss(cve_ids: list[str]) -> dict:
    """Batch-fetch EPSS scores. Returns {cve_id: {"score": float, "percentile": float}}.
    Fails soft to {} so collectors work even if the API is unreachable."""
    if not cve_ids:
        return {}
    out = {}
    # API accepts comma-separated lists; chunk to stay under URL limits.
    for i in range(0, len(cve_ids), 50):
        chunk = cve_ids[i:i + 50]
        try:
            resp = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=20)
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                try:
                    out[row["cve"].upper()] = {
                        "score": round(float(row["epss"]), 4),
                        "percentile": round(float(row["percentile"]), 4),
                    }
                except (KeyError, ValueError):
                    continue
        except requests.RequestException:
            continue
    return out


def unified_priority(kev: bool, ransomware: bool, cvss: float | None, epss: float | None) -> dict:
    """KEV + EPSS + CVSS combined score (0-100) with a visible rationale.
    This mirrors how real VM programs prioritize: confirmed exploitation
    first, predicted exploitation second, theoretical severity third."""
    score = 0
    reasons = []
    if kev:
        score += 40
        reasons.append("Confirmed exploited (CISA KEV).")
    if ransomware:
        score += 15
        reasons.append("Known ransomware campaign use.")
    if epss is not None:
        score += round(epss * 25)
        reasons.append(f"EPSS {epss:.0%} probability of exploitation within 30 days.")
    if cvss is not None:
        if cvss >= 9.0:
            score += 20
        elif cvss >= 7.0:
            score += 12
        elif cvss >= 4.0:
            score += 5
        reasons.append(f"CVSS v3 base score {cvss}.")
    # Floor: very high EPSS is urgent even without KEV listing — this is the
    # "old CVE waking up" case, where prediction precedes confirmation.
    if epss is not None and epss >= 0.7 and score < 60:
        score = 60
        reasons.append("Priority floored at 'Patch within 48h': EPSS >= 70% is a strong exploitation signal even before KEV listing.")
    score = min(score, 100)

    if score >= 80:
        label = "Emergency out-of-band"
    elif score >= 55:
        label = "Patch within 48h"
    elif score >= 30:
        label = "Expedited cycle"
    else:
        label = "Standard cycle"
    return {"priority_score": score, "priority_label": label, "reason": " ".join(reasons)}


# ---------------------------------------------------------------------------
# W5H Intel Brief — structured who/what/when/tech/action/why fields.
# Values are short FACTS (counts, dates, products, versions) or our own
# templated wording — never reproduced prose from the source article.
# ---------------------------------------------------------------------------
IMPACT_COUNT_RE = re.compile(
    r"(\d[\d,.]*\s*(?:million|thousand|billion)?)\s+"
    r"(individuals|users|customers|patients|employees|people|records|accounts|organizations|companies|instances|devices|servers)",
    re.I,
)
ORG_HINT_RE = re.compile(r"^([A-Z][\w&.'-]*(?:\s+[A-Z][\w&.'-]*){0,3})\s+(?:has|have|reported|discloses?d?|announces?d?|confirms?e?d?|suffere?d?s?|warns?e?d?|hit|breached|patche[sd]|fixe[sd]|released?|said)\b", )
DATA_TYPES = ["credentials", "passwords", "personal information", "pii", "customer data",
              "financial data", "payment card", "health records", "medical records",
              "social security", "email addresses", "source code", "customer records"]


def extract_w5h(title: str, text: str, badges: dict, targets: dict,
                affected_versions: str | None, published: str | None,
                due_date: str | None = None) -> dict:
    full = f"{title}. {text or ''}"
    low = full.lower()

    # WHO was impacted — org from title pattern, or scale of impact
    who = None
    m = ORG_HINT_RE.match(title or "")
    if m and m.group(1).lower() not in ("the", "a", "an", "new", "critical", "over", "more"):
        who = m.group(1)
    cm = IMPACT_COUNT_RE.search(full)
    if cm:
        scale = f"{cm.group(1)} {cm.group(2)}".strip()
        who = f"{who} — {scale} affected" if who else f"{scale} affected"
    if not who:
        who = "Not specified in source reporting"

    # WHAT was impacted — data types or the product itself
    hit_types = [d for d in DATA_TYPES if d in low]
    if hit_types:
        what = ", ".join(sorted(set(hit_types))[:3]).title()
    elif targets.get("product"):
        what = f"Systems running {targets['product']}"
    else:
        what = "See source reporting"

    # WHEN
    when = (published or "")[:10] or "Not specified"

    # TECHNOLOGY / APPLICATION
    tech = targets.get("product") or "Not specified in source reporting"
    if targets.get("cve"):
        tech += f" ({targets['cve']})"

    # WHAT TO UPGRADE / ACTION
    if affected_versions and "not provided" not in affected_versions.lower() and "not specified" not in affected_versions.lower():
        action = f"Patch/upgrade {targets.get('product') or 'affected systems'} — affected: {affected_versions}"
    elif targets.get("product"):
        action = f"Apply current vendor patches for {targets['product']} per the advisory"
    else:
        action = "Review the source advisory for remediation guidance"
    if due_date:
        action += f" (CISA remediation due date: {due_date})"

    # WHY IT MATTERS — fully our own templated wording from derived signals
    why_parts = []
    if badges.get("active_exploitation"):
        why_parts.append("exploitation is confirmed or actively occurring, not theoretical")
    epss = badges.get("epss_score")
    if epss is not None and epss >= 0.3:
        why_parts.append(f"EPSS puts exploitation probability at {epss:.0%} within 30 days")
    cvss = badges.get("cvss_score")
    if cvss is not None and cvss >= 9.0:
        why_parts.append("critical severity means full compromise is likely if reached")
    if targets.get("is_appliance"):
        why_parts.append("edge/network devices are internet-facing and a top initial-access vector")
    if any(k in low for k in ("insurance", "insurer", "broker", "financial", "bank", "retirement", "wealth", "benefits")):
        why_parts.append("directly relevant to financial services and insurance sector exposure")
    why = ("This matters because " + "; ".join(why_parts) + ".") if why_parts else \
          "Track for awareness; escalate if the affected technology is in your environment."

    return {
        "who_impacted": who,
        "what_impacted": what,
        "when": when,
        "technology": tech,
        "upgrade_action": action,
        "why_it_matters": why,
    }


# ---------------------------------------------------------------------------
# Impact classification + threat attribution (MSRC-style advisory fields)
# ---------------------------------------------------------------------------
IMPACT_TYPES = [
    ("Remote Code Execution", ["remote code execution", "rce", "execute arbitrary code", "code execution"]),
    ("Authentication Bypass", ["authentication bypass", "auth bypass", "bypass authentication"]),
    ("Privilege Escalation", ["privilege escalation", "elevation of privilege", "local privilege"]),
    ("SQL Injection", ["sql injection", "sqli"]),
    ("Cross-Site Scripting", ["cross-site scripting", "xss"]),
    ("Path Traversal", ["path traversal", "directory traversal"]),
    ("Information Disclosure", ["information disclosure", "data exposure", "exfiltrat", "data leak", "data breach", "unauthorized access to"]),
    ("Denial of Service", ["denial of service", "dos attack", "dos condition"]),
    ("Server-Side Request Forgery", ["server-side request forgery", "ssrf"]),
    ("Credential Theft", ["credential theft", "credential phishing", "steal credentials", "credential harvest", "infostealer", "information stealer", "stealer"]),
    ("Supply Chain Compromise", ["supply chain", "compromised package", "malicious package", "dependency"]),
    ("Account Takeover", ["account takeover", "session hijack"]),
]

# Known threat actor / group / malware family names. Extend freely — this
# powers the "Threat Attribution" advisory field for the IR audience.
THREAT_ACTORS = [
    "LockBit", "ALPHV", "BlackCat", "Cl0p", "Clop", "Akira", "Royal", "Black Basta",
    "Scattered Spider", "Lazarus", "Kimsuky", "APT28", "APT29", "APT41", "Fancy Bear",
    "Cozy Bear", "Volt Typhoon", "Salt Typhoon", "Midnight Blizzard", "Sandworm",
    "FIN7", "FIN11", "TA505", "Qakbot", "Emotet", "Conti", "Ryuk", "Hive",
    "RansomHub", "Medusa", "Play", "8Base", "BianLian", "Rhysida", "Vice Society",
    "Djinn Stealer", "RedLine", "Lumma", "Vidar", "AgentTesla", "Raccoon",
    "Cobalt Strike", "Ousaban", "TaskWeaver",
]


def classify_impact(text: str) -> str | None:
    low = (text or "").lower()
    for label, keywords in IMPACT_TYPES:
        if any(kw in low for kw in keywords):
            return label
    return None


def extract_threat_actors(text: str) -> list[str]:
    found = []
    for actor in THREAT_ACTORS:
        if re.search(r"\b" + re.escape(actor) + r"\b", text or "", re.I):
            canonical = actor
            if canonical not in found:
                found.append(canonical)
    return found[:5]
