#!/usr/bin/env python3
"""
collect_news.py — VulnWire news collector

Pulls cybersecurity news from public RSS feeds, classifies each article into
one or more categories (data breaches, ransomware, vulnerabilities, cyber
insurance), optionally generates a plain-language ANALYSIS summary and a
PROTOCOL RESPONSE (recommended action) via an LLM, and writes the result to
data/news.json.

Scope / guardrails (intentional):
- Public news sources only. Nothing here references any specific
  organization's assets, hostnames, or internal environment.
- The "cyber_insurance" category is for news about the cyber insurance and
  insurance-brokerage industry (breaches, coverage, underwriting, claims,
  regulatory action affecting insurers/brokers) — general industry news,
  never anything about a specific employer's book of business or clients.
- If AI enrichment is off, the article's own RSS summary is used for the
  ANALYSIS text and PROTOCOL RESPONSE is left null.
"""

import hashlib
import html
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import feedparser
import requests

OUTPUT_PATH = Path("data/news.json")
SCHEMA_VERSION = "2.0"

MAX_PER_FEED = int(os.environ.get("VULNWIRE_MAX_PER_FEED", "15"))
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
ENABLE_AI = os.environ.get("VULNWIRE_ENABLE_AI", "false").lower() == "true"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vulnwire-news")

# ---------------------------------------------------------------------------
# RSS FEEDS
# Verify/adjust these URLs — feed paths change over time. Each feed can be
# tagged with a "default_category" that is always applied, plus keyword
# classification runs on every article regardless of source.
# ---------------------------------------------------------------------------
FEEDS = [
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "default_category": None},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "default_category": None},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "default_category": None},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "default_category": None},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "default_category": None},
    {"name": "The Record", "url": "https://therecord.media/feed/", "default_category": None},
    # Insurance-industry trade sources. These feeds cover the broader
    # insurance market; keyword classification narrows to cyber-relevant items.
    {"name": "Insurance Journal", "url": "https://www.insurancejournal.com/rss/news/national/", "default_category": None},
    {"name": "Reinsurance News", "url": "https://www.reinsurancene.ws/feed/", "default_category": None},
]

# ---------------------------------------------------------------------------
# CATEGORY CLASSIFICATION
# An article can belong to multiple categories; the UI filters by membership.
# Order here is also the tab order and the tie-break for "primary" category.
# ---------------------------------------------------------------------------
CATEGORY_KEYWORDS = {
    "data_breaches": [
        "data breach", "breach", "leak", "leaked", "exposed", "exposure",
        "stolen data", "records exposed", "database exposed", "compromised",
        "exfiltrat", "personal information", "pii", "credential",
    ],
    "ransomware": [
        "ransomware", "ransom", "extortion", "encrypted files", "lockbit",
        "blackcat", "alphv", "clop", "double extortion", "data-leak site",
        "ryuk", "conti", "akira", "royal",
    ],
    "vulnerabilities": [
        "vulnerability", "vulnerabilities", "cve-", "zero-day", "zero day",
        "exploit", "flaw", "rce", "remote code execution", "patch",
        "privilege escalation", "buffer overflow", "sql injection",
        "authentication bypass", "0-day",
    ],
    "cyber_insurance": [
        "cyber insurance", "cyber-insurance", "insurer", "insurance",
        "underwriting", "premium", "policyholder", "coverage", "reinsurance",
        "insurance broker", "brokerage", "claims", "loss ratio", "actuar",
        "cyber policy", "cyber cover", "cat bond", "silent cyber",
    ],
}

# Cyber-insurance needs an extra guard: a general breach article shouldn't
# land in the insurance tab just because it says "compromised." Require an
# insurance-domain term to be present for that category specifically.
INSURANCE_REQUIRED_TERMS = [
    "insurance", "insurer", "underwriting", "premium", "policyholder",
    "reinsurance", "brokerage", "broker", "coverage", "cyber policy",
    "loss ratio", "actuar", "cat bond", "silent cyber", "claims",
]

# ---------------------------------------------------------------------------
# Per-category deterministic query guidance for NEWS items. These are generic
# best-practice HINTS about what to look up — never literal queries, never
# asset-specific. Used as a fallback; AI enrichment (if enabled) can override
# with article-specific hints. Insurance guidance is honest that market news
# usually isn't a direct endpoint/scanner target.
# ---------------------------------------------------------------------------
NEWS_QUERY_GUIDANCE = {
    "vulnerabilities": {
        "tanium_hint": "Look up the affected product and version across managed endpoints (installed-application name + version), then cross-reference network exposure for anything internet-facing.",
        "rapid7_hint": "Search InsightVM for the CVE ID or the vendor advisory's associated check; prefer an authenticated/active check over a version-only match where one exists.",
    },
    "ransomware": {
        "tanium_hint": "Look up the initial-access software or CVE this actor is known to abuse; check patch state and presence of the vulnerable component across endpoints.",
        "rapid7_hint": "Confirm the initial-access vulnerabilities tied to this actor are covered by your scan templates, and validate remediation on any matches.",
    },
    "data_breaches": {
        "tanium_hint": "If a specific product, agent, or credential type is implicated, look up its presence and version across endpoints; for credential exposure, review the affected software and related persistence.",
        "rapid7_hint": "Scan for the affected software or misconfiguration called out in the report, and confirm exposure of any service/port named as the entry point.",
    },
    "cyber_insurance": {
        "tanium_hint": "Industry/market news — not a direct endpoint query. If a specific breached product is named, look up its presence and version across endpoints for awareness.",
        "rapid7_hint": "Industry/market news — no direct scan action. Use for risk-posture and control-attestation context (MFA, EDR, patch SLAs) that underwriters increasingly require at renewal.",
    },
    "default": {
        "tanium_hint": "If a specific affected product is named, look up its presence and version across managed endpoints.",
        "rapid7_hint": "If a specific affected product or CVE is named, confirm coverage in your scan templates and validate any matches.",
    },
}


def news_guidance_for(categories: list[str]) -> dict:
    for cat in categories:
        if cat in NEWS_QUERY_GUIDANCE:
            return NEWS_QUERY_GUIDANCE[cat]
    return NEWS_QUERY_GUIDANCE["default"]


def clean_text(raw: str) -> str:
    """Strip HTML tags/entities from an RSS summary to get plain text."""
    if not raw:
        return ""
    no_tags = re.sub(r"<[^>]+>", " ", raw)
    unescaped = html.unescape(no_tags)
    return re.sub(r"\s+", " ", unescaped).strip()


def classify(title: str, summary: str, default_category: str | None) -> list[str]:
    text = f"{title} {summary}".lower()
    cats: list[str] = []

    for category, keywords in CATEGORY_KEYWORDS.items():
        if category == "cyber_insurance":
            # Require a genuine insurance-domain term, not just any keyword.
            if any(term in text for term in INSURANCE_REQUIRED_TERMS):
                cats.append(category)
            continue
        if any(kw in text for kw in keywords):
            cats.append(category)

    if default_category and default_category not in cats:
        cats.append(default_category)

    return cats


def ai_enrich(title: str, summary: str) -> dict:
    """Optional LLM enrichment -> {analysis, tanium_hint, rapid7_hint}.
    Any field may be None; the caller fills None hints from the
    deterministic per-category library. Fails soft when disabled/on error."""
    empty = {"analysis": summary or None, "tanium_hint": None, "rapid7_hint": None}
    if not (ENABLE_AI and OPENAI_API_KEY):
        return empty

    prompt = (
        "You are a cybersecurity news analyst assistant. Given the headline "
        "and summary below, return STRICT JSON only (no markdown, no "
        'commentary) with exactly three keys:\n'
        '1) "analysis": 2-3 plain sentences on what happened and the risk.\n'
        '2) "tanium_hint": one short hint on WHAT TO LOOK UP in Tanium for '
        "this story (a general approach — e.g. which product/version or "
        "exposure to query). NOT a literal query string.\n"
        '3) "rapid7_hint": one short hint on WHAT TO RESEARCH in Rapid7 / '
        "InsightVM for this story (which CVE, check, or scan template).\n"
        "Rules: do NOT invent specifics not in the source. Do NOT reference "
        "any particular organization's asset names, hostnames, or internal "
        "environment. If the story is market/industry news with no technical "
        "target, say so plainly in the hint rather than inventing one.\n\n"
        f"Headline: {title}\nSummary: {summary}"
    )
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
                "temperature": 0.3,
            },
            timeout=30,
        )
        resp.raise_for_status()
        parsed = json.loads(resp.json()["choices"][0]["message"]["content"])
        return {
            "analysis": parsed.get("analysis") or summary or None,
            "tanium_hint": parsed.get("tanium_hint"),
            "rapid7_hint": parsed.get("rapid7_hint"),
        }
    except (requests.RequestException, KeyError, json.JSONDecodeError) as exc:
        log.warning("AI enrichment failed for '%s': %s", title[:60], exc)
        return empty


def make_id(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:12]


def parse_published(entry) -> str | None:
    for attr in ("published_parsed", "updated_parsed"):
        val = getattr(entry, attr, None)
        if val:
            return datetime(*val[:6], tzinfo=timezone.utc).isoformat(timespec="seconds")
    return None


def collect_feed(feed: dict) -> list[dict]:
    log.info("Fetching feed: %s", feed["name"])
    try:
        parsed = feedparser.parse(feed["url"])
    except Exception as exc:  # feedparser is very tolerant, but be safe
        log.warning("Failed to parse %s: %s", feed["name"], exc)
        return []

    items = []
    for entry in parsed.entries[:MAX_PER_FEED]:
        title = clean_text(getattr(entry, "title", ""))
        summary = clean_text(getattr(entry, "summary", "") or getattr(entry, "description", ""))
        url = getattr(entry, "link", "")
        if not (title and url):
            continue

        categories = classify(title, summary, feed["default_category"])
        if not categories:
            continue  # skip articles that don't fit any tracked category

        enrichment = ai_enrich(title, summary)
        guidance = news_guidance_for(categories)

        items.append({
            "id": make_id(url),
            "type": "news",
            "title": title,
            "source": feed["name"],
            "url": url,
            "published": parse_published(entry),
            "categories": categories,
            "analysis": enrichment["analysis"],
            "tanium_hint": enrichment["tanium_hint"] or guidance["tanium_hint"],
            "rapid7_hint": enrichment["rapid7_hint"] or guidance["rapid7_hint"],
        })
    log.info("  -> %d classified items from %s", len(items), feed["name"])
    return items


def dedupe(items: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for item in items:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        out.append(item)
    return out


def main() -> None:
    all_items: list[dict] = []
    for feed in FEEDS:
        all_items.extend(collect_feed(feed))

    all_items = dedupe(all_items)
    all_items.sort(key=lambda i: i.get("published") or "", reverse=True)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "categories": list(CATEGORY_KEYWORDS.keys()),
        "item_count": len(all_items),
        "items": all_items,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2))
    log.info("Wrote %d news items to %s", len(all_items), OUTPUT_PATH)


if __name__ == "__main__":
    main()
