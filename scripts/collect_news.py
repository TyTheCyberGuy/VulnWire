#!/usr/bin/env python3
"""
collect_news.py - VulnWire news collector (no paid APIs)

Pulls cybersecurity news from public RSS feeds, classifies each article into
categories (data breaches, ransomware, vulnerabilities, cyber insurance),
fetches the full article text where possible, and synthesizes a fact-dense
ANALYSIS plus badges (active exploitation / CVSS / priority), IMPACT & SCOPE,
CVE cross-references, and a structured W5H intel brief. Writes data/news.json.

Everything is free and deterministic. No API keys required.

Deduplication: items are deduped by URL hash AND normalized title across ALL
feeds. The highest-priority version (KEV > EPSS > CVSS > date) is kept when
the same story appears in multiple outlets.

Ad / noise filtering: items are dropped if they match ad/promo signals
(no CVE, no security keyword, short title, commercial-only language).
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
SCHEMA_VERSION = "3.2"

MAX_PER_FEED = int(os.environ.get("VULNWIRE_MAX_PER_FEED", "15"))
FETCH_ARTICLES = os.environ.get("VULNWIRE_FETCH_ARTICLES", "false").lower() == "true"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vulnwire-news")

FEEDS = [
    # Security news media
    {"name": "The Hacker News",            "url": "https://feeds.feedburner.com/TheHackersNews",                                    "source_type": "news"},
    {"name": "BleepingComputer",           "url": "https://www.bleepingcomputer.com/feed/",                                         "source_type": "news"},
    {"name": "Krebs on Security",          "url": "https://krebsonsecurity.com/feed/",                                              "source_type": "news"},
    {"name": "Dark Reading",               "url": "https://www.darkreading.com/rss/all.xml",                                        "source_type": "news"},
    {"name": "SecurityWeek",               "url": "https://www.securityweek.com/feed/",                                             "source_type": "news"},
    {"name": "The Record",                 "url": "https://therecord.media/feed/",                                                  "source_type": "news"},
    {"name": "Ars Technica Security",      "url": "https://arstechnica.com/tag/security/feed/",                                     "source_type": "news"},
    {"name": "Security Affairs",           "url": "http://securityaffairs.co/wordpress/feed",                                       "source_type": "news"},
    {"name": "Graham Cluley",              "url": "https://www.grahamcluley.com/feed/",                                             "source_type": "news"},
    {"name": "Infosecurity Magazine",      "url": "http://www.infosecurity-magazine.com/rss/news/",                                 "source_type": "news"},
    {"name": "Schneier on Security",       "url": "https://www.schneier.com/blog/atom.xml",                                         "source_type": "news"},
    {"name": "Troy Hunt",                  "url": "https://www.troyhunt.com/rss/",                                                  "source_type": "news"},
    {"name": "HackerOne",                  "url": "https://www.hackerone.com/blog.rss",                                             "source_type": "news"},
    # Insurance industry
    {"name": "Insurance Journal",          "url": "https://www.insurancejournal.com/rss/news/national/",                            "source_type": "news"},
    {"name": "Reinsurance News",           "url": "https://www.reinsurancene.ws/feed/",                                             "source_type": "news"},
    # Vendor / first-party research
    {"name": "Tenable Research",           "url": "https://www.tenable.com/blog/feed",                                             "source_type": "vendor_research"},
    {"name": "Wiz Research",               "url": "https://www.wiz.io/feed/rss.xml",                                               "source_type": "vendor_research"},
    {"name": "Unit 42 (Palo Alto)",        "url": "https://unit42.paloaltonetworks.com/feed/",                                      "source_type": "vendor_research"},
    {"name": "Cisco Talos",                "url": "https://blog.talosintelligence.com/rss/",                                        "source_type": "vendor_research"},
    {"name": "Google Project Zero",        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",             "source_type": "vendor_research"},
    {"name": "Check Point Research",       "url": "https://research.checkpoint.com/feed/",                                          "source_type": "vendor_research"},
    {"name": "SentinelOne Labs",           "url": "https://www.sentinelone.com/labs/feed/",                                         "source_type": "vendor_research"},
    {"name": "Qualys Blog",                "url": "https://blog.qualys.com/feed",                                                   "source_type": "vendor_research"},
    {"name": "Microsoft MSRC",             "url": "https://msrc.microsoft.com/blog/feed",                                           "source_type": "vendor_research"},
    {"name": "Microsoft Security Blog",    "url": "https://www.microsoft.com/security/blog/feed/",                                  "source_type": "vendor_research"},
    {"name": "watchTowr Labs",             "url": "https://labs.watchtowr.com/rss/",                                                "source_type": "vendor_research"},
    {"name": "Horizon3 Attack Research",   "url": "https://horizon3.ai/feed/",                                                      "source_type": "vendor_research"},
    {"name": "ZDI Published Advisories",   "url": "https://www.zerodayinitiative.com/rss/published/",                               "source_type": "vendor_research"},
    {"name": "Crowdstrike Threat Research","url": "https://www.crowdstrike.com/blog/category/threat-intel-research/feed",           "source_type": "vendor_research"},
    {"name": "Recorded Future Threat Intel","url": "https://www.recordedfuture.com/category/threat-intelligence/feed/",            "source_type": "vendor_research"},
    {"name": "Recorded Future Vuln Mgmt", "url": "https://www.recordedfuture.com/category/vulnerability-management/feed/",         "source_type": "vendor_research"},
    {"name": "Mandiant",                   "url": "https://www.mandiant.com/resources/blog/rss.xml",                                "source_type": "vendor_research"},
    {"name": "Bitdefender Labs",           "url": "https://www.bitdefender.com/blog/api/rss/labs/",                                 "source_type": "vendor_research"},
    {"name": "EclecticIQ",                 "url": "https://blog.eclecticiq.com/rss.xml",                                            "source_type": "vendor_research"},
    {"name": "Malwarebytes Labs",          "url": "https://blog.malwarebytes.com/feed/",                                            "source_type": "vendor_research"},
    {"name": "SecureList (Kaspersky)",     "url": "https://securelist.com/feed/",                                                   "source_type": "vendor_research"},
    {"name": "Proofpoint",                 "url": "https://www.proofpoint.com/us/rss.xml",                                          "source_type": "vendor_research"},
    {"name": "IBM Security Intelligence",  "url": "https://securityintelligence.com/feed/",                                         "source_type": "vendor_research"},
    {"name": "Fortinet Threat Research",   "url": "http://feeds.feedburner.com/fortinet/blog/threat-research",                      "source_type": "vendor_research"},
    {"name": "Trend Micro",                "url": "http://feeds.trendmicro.com/TrendMicroSimplySecurity",                           "source_type": "vendor_research"},
    {"name": "VirusTotal Blog",            "url": "https://blog.virustotal.com/feeds/posts/default",                                "source_type": "vendor_research"},
    {"name": "Intezer",                    "url": "https://www.intezer.com/blog/feed/",                                             "source_type": "vendor_research"},
    {"name": "Cofense",                    "url": "https://cofense.com/feed/",                                                      "source_type": "vendor_research"},
    {"name": "Digital Shadows",            "url": "https://www.digitalshadows.com/blog-and-research/feed/",                         "source_type": "vendor_research"},
    {"name": "SpecterOps",                 "url": "https://posts.specterops.io/feed",                                               "source_type": "vendor_research"},
    {"name": "Quarkslab",                  "url": "https://blog.quarkslab.com/feeds/all.rss.xml",                                   "source_type": "vendor_research"},
    {"name": "Secureworks",                "url": "https://www.secureworks.com/rss?feed=blog&category=research-intelligence",        "source_type": "vendor_research"},
    {"name": "Google Online Security",     "url": "https://googleonlinesecurity.blogspot.com/atom.xml",                             "source_type": "vendor_research"},
    {"name": "Broadcom Symantec",          "url": "https://sed-cms.broadcom.com/rss/v1/blogs/rss.xml",                              "source_type": "vendor_research"},
    {"name": "Anomali",                    "url": "https://www.anomali.com/site/blog-rss",                                          "source_type": "vendor_research"},
    {"name": "Cloudflare Security",        "url": "https://blog.cloudflare.com/tag/security/rss",                                   "source_type": "vendor_research"},
    {"name": "Fox-IT",                     "url": "https://blog.fox-it.com/feed/",                                                  "source_type": "vendor_research"},
    {"name": "0patch Blog",                "url": "https://blog.0patch.com/feeds/posts/default",                                    "source_type": "vendor_research"},
    {"name": "Virus Bulletin",             "url": "https://www.virusbulletin.com/rss",                                              "source_type": "vendor_research"},
    # Government / community advisories
    {"name": "CISA Advisories",            "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",                          "source_type": "gov_advisory"},
    {"name": "SANS ISC",                   "url": "https://isc.sans.edu/rssfeed_full.xml",                                          "source_type": "gov_advisory"},
    {"name": "CIS Advisories",             "url": "https://www.cisecurity.org/feed/advisories",                                     "source_type": "gov_advisory"},
    {"name": "NIST Cybersecurity",         "url": "https://www.nist.gov/blogs/cybersecurity-insights/rss.xml",                      "source_type": "gov_advisory"},
    {"name": "US-CERT Alerts",             "url": "https://us-cert.cisa.gov/ncas/alerts.xml",                                       "source_type": "gov_advisory"},
    {"name": "US-CERT Current Activity",   "url": "https://us-cert.cisa.gov/ncas/current-activity.xml",                             "source_type": "gov_advisory"},
    {"name": "US-CERT Analysis Reports",   "url": "https://us-cert.cisa.gov/ncas/analysis-reports.xml",                             "source_type": "gov_advisory"},
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
        "ryuk", "conti", "akira", "royal", "medusa", "play ransomware",
        "rhysida", "hunters international", "inc ransom",
    ],
    "vulnerabilities": [
        "vulnerability", "vulnerabilities", "cve-", "zero-day", "zero day",
        "exploit", "flaw", "rce", "remote code execution", "patch",
        "privilege escalation", "buffer overflow", "sql injection",
        "authentication bypass", "0-day", "unauthenticated",
    ],
    "zero_day": [
        "zero-day", "zero day", "0-day", "0day", "no patch available",
        "unpatched vulnerability", "before a patch", "prior to patch availability",
        "actively exploited before patch",
    ],
    "financial_services": [
        "financial services", "bank", "banking", "fintech", "credit union",
        "retirement", "401(k)", "401k", "pension", "annuit", "private wealth",
        "wealth management", "asset management", "brokerage", "broker-dealer",
        "employee benefits", "payroll", "finra", "sec ", "nydfs", "glba",
        "investment firm", "hedge fund", "mutual fund", "insurance", "insurer",
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

AD_SIGNALS_RE = re.compile(
    r"\b(sponsored|advertisement|affiliate|deal of the day|buy now|"
    r"discount|free trial|webinar|whitepaper|e-?book|download now|"
    r"register now|join us|learn more at)\b",
    re.I,
)

INTEL_SIGNALS_RE = re.compile(
    r"(CVE-\d{4}-\d+|exploit|vulnerab|breach|ransomware|malware|phish|"
    r"patch|zero.?day|threat actor|incident|attack|compromise|cisa|nvd|"
    r"authentication bypass|remote code|privilege escalation|credential)",
    re.I,
)


def is_ad_or_noise(title, summary):
    text = title + " " + summary
    if AD_SIGNALS_RE.search(text):
        return True
    if len(title.strip()) < 20 and not INTEL_SIGNALS_RE.search(text):
        return True
    noise_re = re.compile(
        r"^(join|register|attend|save the date|announcing|award|winner|"
        r"congratulations|upcoming event|live event|free guide|new guide)",
        re.I,
    )
    if noise_re.match(title.strip()) and not INTEL_SIGNALS_RE.search(text):
        return True
    return False


def clean_text(raw):
    if not raw:
        return ""
    no_tags = re.sub(r"<[^>]+>", " ", raw)
    return re.sub(r"\s+", " ", html.unescape(no_tags)).strip()


def classify(title, summary):
    text = (title + " " + summary).lower()
    cats = []
    for category, keywords in CATEGORY_KEYWORDS.items():
        if category == "cyber_insurance":
            if any(term in text for term in INSURANCE_REQUIRED_TERMS):
                cats.append(category)
            continue
        if any(kw in text for kw in keywords):
            cats.append(category)
    return cats


def make_id(url):
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:12]


def parse_published(entry):
    for attr in ("published_parsed", "updated_parsed"):
        val = getattr(entry, attr, None)
        if val:
            return datetime(*val[:6], tzinfo=timezone.utc).isoformat(timespec="seconds")
    return None


def normalize_title_key(title):
    t = title.lower()
    t = re.sub(r"[^a-z0-9\s]", "", t)
    t = re.sub(r"\s+", " ", t).strip()
    stopwords = {
        "the", "a", "an", "in", "on", "at", "to", "of", "and", "or", "for",
        "with", "how", "why", "what", "new", "says", "report", "analysis",
        "via", "as", "is", "are", "was", "were", "has", "have", "had", "be", "been",
    }
    words = [w for w in t.split() if w not in stopwords]
    return " ".join(words[:12])


def collect_feed(feed):
    log.info("Fetching feed: %s", feed["name"])
    try:
        parsed = feedparser.parse(feed["url"])
    except Exception as exc:
        log.warning("Failed to parse %s: %s", feed["name"], exc)
        return []

    items = []
    for entry in parsed.entries[:MAX_PER_FEED]:
        title = clean_text(getattr(entry, "title", ""))
        rss_summary = clean_text(
            getattr(entry, "summary", "") or getattr(entry, "description", "")
        )
        url = getattr(entry, "link", "")
        if not (title and url):
            continue
        if is_ad_or_noise(title, rss_summary):
            log.debug("Dropping ad/noise: %s", title[:80])
            continue
        categories = classify(title, rss_summary)
        if not categories:
            continue

        article_text = enrich.fetch_article_text(url) if FETCH_ARTICLES else None
        full_context = title + ". " + (article_text or rss_summary)

        badges = enrich.extract_badges(full_context)
        targets = guidance.extract_targets(full_context)
        impact = enrich.extract_impact(
            full_context,
            targets.get("product"),
            targets.get("is_appliance", False),
            targets.get("special"),
        )
        cve_ids = enrich.extract_cves(full_context)
        w5h = enrich.extract_w5h(
            title,
            article_text or rss_summary,
            badges,
            targets,
            impact.get("affected_versions"),
            parse_published(entry),
        )
        impact_type = enrich.classify_impact(full_context)
        threat_actors = enrich.extract_threat_actors(full_context)

        items.append({
            "id":            make_id(url),
            "type":          "news",
            "source_type":   feed.get("source_type", "news"),
            "title":         title,
            "_title_key":    normalize_title_key(title),
            "source":        feed["name"],
            "url":           url,
            "published":     parse_published(entry),
            "categories":    categories,
            "w5h":           w5h,
            "impact_type":   impact_type,
            "threat_actors": threat_actors,
            "badges":        badges,
            "impact":        impact,
            "cve_ids":       cve_ids,
        })

    log.info("  -> %d classified items from %s", len(items), feed["name"])
    return items


def dedupe(items):
    def quality_score(item):
        b = item.get("badges", {})
        score = 0
        if b.get("active_exploitation"):
            score += 100
        score += (b.get("cvss_score") or 0) * 5
        score += (b.get("epss_score") or 0) * 20
        if item.get("source_type") == "gov_advisory":
            score += 10
        if item.get("source_type") == "vendor_research":
            score += 5
        return score

    sorted_items = sorted(items, key=quality_score, reverse=True)
    seen_ids, seen_titles, out = set(), set(), []
    for item in sorted_items:
        tid = normalize_title_key(item.get("title", ""))
        if item["id"] in seen_ids or (tid and tid in seen_titles):
            continue
        seen_ids.add(item["id"])
        if tid:
            seen_titles.add(tid)
        out.append(item)
    return out


RETENTION_DAYS = int(os.environ.get("VULNWIRE_RETENTION_DAYS", "21"))


def load_previous():
    try:
        prev = json.loads(OUTPUT_PATH.read_text())
        return {i["id"]: i for i in prev.get("items", [])}
    except (OSError, json.JSONDecodeError, KeyError):
        return {}


def strip_internal_keys(items):
    return [{k: v for k, v in item.items() if not k.startswith("_")} for item in items]


def main():
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
        log.warning(
            "Feeds returning 0 items (dead URL or no matching articles): %s",
            ", ".join(dead),
        )

    all_items = dedupe(all_items)

    for item in all_items:
        old = previous.get(item["id"]) or {}
        item["first_seen"] = old.get("first_seen") or now.isoformat(timespec="seconds")

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

    all_cves = sorted({c for i in all_items for c in (i.get("cve_ids") or [])})
    epss_map = enrich.fetch_epss(all_cves)
    log.info("EPSS scores retrieved for %d/%d CVEs", len(epss_map), len(all_cves))

    for item in all_items:
        cves = item.get("cve_ids") or []
        scores = [epss_map[c]["score"] for c in cves if c in epss_map]
        item.setdefault("badges", {})
        if scores:
            item["badges"]["epss_score"] = max(scores)
        elif "epss_score" not in item["badges"]:
            item["badges"]["epss_score"] = None

    all_items.sort(key=lambda i: i.get("published") or "", reverse=True)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at":   now.isoformat(timespec="seconds"),
        "source_run_id":  os.environ.get("GITHUB_RUN_ID", "local"),
        "categories":     list(CATEGORY_KEYWORDS.keys()),
        "feed_health":    feed_health,
        "item_count":     len(all_items),
        "items":          strip_internal_keys(all_items),
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2))
    log.info(
        "Wrote %d news items to %s (%d carried from archive)",
        len(all_items),
        OUTPUT_PATH,
        len(all_items) - len(current_ids),
    )


if __name__ == "__main__":
    main()
