#!/usr/bin/env python3
"""
collect_news.py — VulnWire news collector (no paid APIs)

Pulls cybersecurity news from public RSS feeds, classifies each article into
categories (data breaches, ransomware, vulnerabilities, cyber insurance),
fetches the full article text where possible, and synthesizes a fact-dense
ANALYSIS plus badges (active exploitation / CVSS / priority), IMPACT & SCOPE,
CVE cross-references, and Tanium/Rapid7 hints. Writes data/news.json.

Everything is free and deterministic: full-text fetch + extractive
summarization + rule-based extraction. No API keys required.

Scope guardrails: public news sources only; nothing references any specific
organization's assets, hostnames, or internal environment. The
"cyber_insurance" category tracks insurer/broker industry news, never any
employer's or client's data.
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

import enrich
import guidance

OUTPUT_PATH = Path("data/news.json")
SCHEMA_VERSION = "3.0"

MAX_PER_FEED = int(os.environ.get("VULNWIRE_MAX_PER_FEED", "15"))
FETCH_ARTICLES = os.environ.get("VULNWIRE_FETCH_ARTICLES", "true").lower() == "true"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vulnwire-news")

# Verify/adjust these URLs — feed paths change over time. Every feed fails
# soft (a dead URL just logs a warning and contributes zero items), and each
# run logs a per-feed health summary so dead feeds are easy to spot and fix.
#
# source_type controls the card tag:
#   news            -> no tag (default)
#   vendor_research -> "RESEARCH" tag (first-party vuln research)
#   gov_advisory    -> "ADVISORY" tag (government advisories)
FEEDS = [
    # --- Security news media ---
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "source_type": "news"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "source_type": "news"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "source_type": "news"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "source_type": "news"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "source_type": "news"},
    {"name": "The Record", "url": "https://therecord.media/feed/", "source_type": "news"},

    # --- Vendor / first-party vulnerability research ---
    {"name": "Rapid7 Research", "url": "https://blog.rapid7.com/rss/", "source_type": "vendor_research"},
    {"name": "Tenable Research", "url": "https://www.tenable.com/blog/feed", "source_type": "vendor_research"},
    {"name": "Wiz Research", "url": "https://www.wiz.io/feed/rss.xml", "source_type": "vendor_research"},
    {"name": "Unit 42 (Palo Alto)", "url": "https://unit42.paloaltonetworks.com/feed/", "source_type": "vendor_research"},
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/", "source_type": "vendor_research"},
    {"name": "Google Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss", "source_type": "vendor_research"},
    {"name": "Check Point Research", "url": "https://research.checkpoint.com/feed/", "source_type": "vendor_research"},
    {"name": "SentinelOne Labs", "url": "https://www.sentinelone.com/labs/feed/", "source_type": "vendor_research"},
    {"name": "Qualys Blog", "url": "https://blog.qualys.com/feed", "source_type": "vendor_research"},
    {"name": "Microsoft MSRC", "url": "https://msrc.microsoft.com/blog/feed", "source_type": "vendor_research"},
    {"name": "watchTowr Labs", "url": "https://labs.watchtowr.com/rss/", "source_type": "vendor_research"},
    {"name": "Horizon3 Attack Research", "url": "https://horizon3.ai/feed/", "source_type": "vendor_research"},
    {"name": "ZDI Published Advisories", "url": "https://www.zerodayinitiative.com/rss/published/", "source_type": "vendor_research"},

    # --- Government / community advisories ---
    {"name": "CISA Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "source_type": "gov_advisory"},
    {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml", "source_type": "gov_advisory"},

    # --- Insurance industry ---
    {"name": "Insurance Journal", "url": "https://www.insurancejournal.com/rss/news/national/", "source_type": "news"},
    {"name": "Reinsurance News", "url": "https://www.reinsurancene.ws/feed/", "source_type": "news"},
]

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

INSURANCE_REQUIRED_TERMS = [
    "insurance", "insurer", "underwriting", "premium", "policyholder",
    "reinsurance", "brokerage", "broker", "coverage", "cyber policy",
    "loss ratio", "actuar", "cat bond", "silent cyber", "claims",
]


def clean_text(raw: str) -> str:
    if not raw:
        return ""
    no_tags = re.sub(r"<[^>]+>", " ", raw)
    return re.sub(r"\s+", " ", html.unescape(no_tags)).strip()


def classify(title: str, summary: str) -> list[str]:
    text = f"{title} {summary}".lower()
    cats = []
    for category, keywords in CATEGORY_KEYWORDS.items():
        if category == "cyber_insurance":
            if any(term in text for term in INSURANCE_REQUIRED_TERMS):
                cats.append(category)
            continue
        if any(kw in text for kw in keywords):
            cats.append(category)
    return cats


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
    except Exception as exc:
        log.warning("Failed to parse %s: %s", feed["name"], exc)
        return []

    items = []
    for entry in parsed.entries[:MAX_PER_FEED]:
        title = clean_text(getattr(entry, "title", ""))
        rss_summary = clean_text(getattr(entry, "summary", "") or getattr(entry, "description", ""))
        url = getattr(entry, "link", "")
        if not (title and url):
            continue

        categories = classify(title, rss_summary)
        if not categories:
            continue

        # Full-text fetch for a richer analysis (falls back to RSS summary).
        article_text = enrich.fetch_article_text(url) if FETCH_ARTICLES else None
        full_context = f"{title}. {article_text or rss_summary}"

        analysis = enrich.synthesize_analysis(title, rss_summary, article_text)
        badges = enrich.extract_badges(full_context)
        targets = guidance.extract_targets(full_context)
        impact = enrich.extract_impact(
            full_context, targets.get("product"),
            targets.get("is_appliance", False), targets.get("special"),
        )
        hints = {
            "tanium_hint": guidance.tanium_hint(targets),
            "rapid7_hint": guidance.rapid7_hint(targets),
        }
        cve_ids = enrich.extract_cves(full_context)

        items.append({
            "id": make_id(url),
            "type": "news",
            "source_type": feed.get("source_type", "news"),
            "title": title,
            "source": feed["name"],
            "url": url,
            "published": parse_published(entry),
            "categories": categories,
            "analysis": analysis,
            "badges": badges,
            "impact": impact,
            "cve_ids": cve_ids,
            "tanium_hint": hints["tanium_hint"],
            "rapid7_hint": hints["rapid7_hint"],
        })
    log.info("  -> %d classified items from %s", len(items), feed["name"])
    return items


def dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for item in items:
        if item["id"] not in seen:
            seen.add(item["id"])
            out.append(item)
    return out


RETENTION_DAYS = int(os.environ.get("VULNWIRE_RETENTION_DAYS", "21"))


def load_previous() -> dict:
    """Previous run's items keyed by id — enables persistence and first_seen."""
    try:
        prev = json.loads(OUTPUT_PATH.read_text())
        return {i["id"]: i for i in prev.get("items", [])}
    except (OSError, json.JSONDecodeError, KeyError):
        return {}


def main() -> None:
    now = datetime.now(timezone.utc)
    previous = load_previous()

    all_items = []
    feed_health = {}
    for feed in FEEDS:
        got = collect_feed(feed)
        feed_health[feed["name"]] = len(got)
        all_items.extend(got)
    dead = [n for n, c in feed_health.items() if c == 0]
    if dead:
        log.warning("Feeds returning 0 items (dead URL or no matching articles): %s", ", ".join(dead))
    all_items = dedupe(all_items)

    # Persistence: keep first_seen from previous runs; new items get stamped now.
    for item in all_items:
        old = previous.get(item["id"]) or {}
        item["first_seen"] = old.get("first_seen") or now.isoformat(timespec="seconds")

    # Carry forward recent items that dropped out of the RSS window (archive).
    current_ids = {i["id"] for i in all_items}
    cutoff = now.timestamp() - RETENTION_DAYS * 86400
    for old_id, old_item in previous.items():
        if old_id in current_ids:
            continue
        ts = old_item.get("published") or old_item.get("first_seen") or ""
        try:
            if datetime.fromisoformat(ts).timestamp() >= cutoff:
                all_items.append(old_item)
        except ValueError:
            continue

    # EPSS enrichment across every CVE referenced anywhere.
    all_cves = sorted({c for i in all_items for c in (i.get("cve_ids") or [])})
    epss_map = enrich.fetch_epss(all_cves)
    log.info("EPSS scores retrieved for %d/%d CVEs", len(epss_map), len(all_cves))
    for item in all_items:
        cves = item.get("cve_ids") or []
        scores = [epss_map[c]["score"] for c in cves if c in epss_map]
        item.setdefault("badges", {})
        item["badges"]["epss_score"] = max(scores) if scores else None

    all_items.sort(key=lambda i: i.get("published") or "", reverse=True)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now.isoformat(timespec="seconds"),
        "source_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "categories": list(CATEGORY_KEYWORDS.keys()),
        "feed_health": feed_health,
        "item_count": len(all_items),
        "items": all_items,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2))
    log.info("Wrote %d news items to %s (%d carried from archive)",
             len(all_items), OUTPUT_PATH, len(all_items) - len(current_ids))


if __name__ == "__main__":
    main()
