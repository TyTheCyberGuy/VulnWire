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
    """Optional LLM enrichment -> {analysis, protocol_response}.
    Fails soft to (summary, None) when disabled or on error."""
    if not (ENABLE_AI and OPENAI_API_KEY):
        return {"analysis": summary or None, "protocol_response": None}

    prompt = (
        "You are a cybersecurity news analyst. Given the headline and summary "
        "below, return STRICT JSON only (no markdown, no commentary) with "
        'exactly two keys: "analysis" (2-3 plain sentences explaining what '
        'happened and the risk) and "protocol_response" (2-3 sentences of '
        "general, best-practice defensive guidance any organization could "
        "act on). Do NOT invent specifics not in the source, and do NOT "
        "reference any particular organization's internal assets or "
        f"environment.\n\nHeadline: {title}\nSummary: {summary}"
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
            "protocol_response": parsed.get("protocol_response"),
        }
    except (requests.RequestException, KeyError, json.JSONDecodeError) as exc:
        log.warning("AI enrichment failed for '%s': %s", title[:60], exc)
        return {"analysis": summary or None, "protocol_response": None}


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

        items.append({
            "id": make_id(url),
            "type": "news",
            "title": title,
            "source": feed["name"],
            "url": url,
            "published": parse_published(entry),
            "categories": categories,
            "analysis": enrichment["analysis"],
            "protocol_response": enrichment["protocol_response"],
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
