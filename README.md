# VulnWire

A static cybersecurity threat-intel node, hosted on GitHub Pages, powered by
scheduled GitHub Actions collectors. **No paid APIs, no live backend, no
environment data.** Everything runs free.

## What it shows

Tabbed card feed: **Data Breaches · Ransomware · Vulnerabilities · Cyber
Insurance · History · CVE Reports**

Each news/CVE card has:
- Clickable headline + publication date (newest first) + source badge
- Badge row: **NEW** (first seen <48h) / **ACTIVE EXPLOITATION** / **CVSS** /
  **EPSS exploit probability** / **Priority** (Emergency out-of-band → Patch
  within 48h → Expedited cycle → Standard cycle)
- **ANALYSIS & TL;DR** — fact-dense summary (see "How analysis works" below)
- **IMPACT & SCOPE** — affected versions (or an honest "assume all until
  vendor clarifies") + how to determine impact for that product class
- **Tanium Query Hint** and **Rapid7 Hint** — product/CVE-aware guidance
  patterns (never literal queries, never asset names)

The **CVE Reports** tab is a CVE Intelligence Tracker: every CVE mentioned
anywhere in the feed gets a card with an NVD DB link and cross-references to
each intelligence report that mentions it, searchable by CVE ID or keyword.

## Prioritization (KEV + EPSS + CVSS)

Priority is a unified 0–100 score with a visible rationale, mirroring how
real VM programs triage: confirmed exploitation (CISA KEV, +40) and known
ransomware use (+15) first, predicted exploitation (EPSS probability from
FIRST.org's free API, up to +25) second, theoretical severity (CVSS, up to
+20) last. Each CVE card shows the "why" — e.g. *"Confirmed exploited (CISA
KEV). EPSS 94% probability of exploitation within 30 days. CVSS 9.8."*

## EPSS surge detection (old CVEs waking up)

An old CVE that starts being exploited will eventually reach CISA KEV (KEV is
keyed on exploitation evidence, not CVE age — the collector sorts by
`dateAdded`, so it surfaces automatically) and the security press. But EPSS
usually moves first. `scripts/collect_epss_movers.py` downloads FIRST.org's
full daily EPSS snapshot (free, no key), diffs it against the previous run
(`data/epss_state.json`), and flags CVEs whose exploitation probability
jumped by >= 0.20 or crossed 0.50 (min score 0.35, top 10 per run,
all tunable via env vars). Movers are enriched from NVD and rendered as
purple "EPSS Surge" cards; EPSS >= 70% floors priority at "Patch within
48h" even without KEV listing. First run writes a baseline and reports zero
movers; surges appear from the second run onward.

## Persistent history

Each run merges with the previous `news.json` instead of overwriting it:
items keep their original `first_seen` timestamp (powering the NEW badge and
the "New (Last 48h)" stat), and stories that drop out of the RSS window are
carried forward for `VULNWIRE_RETENTION_DAYS` (default 21) as an archive.

## How analysis works (free, no LLM)

The collector fetches each article's full text (RSS summaries are often
truncated), then builds the analysis extractively: the lead sentence plus the
most fact-dense sentences — counts of affected users/records, CVE IDs,
versions, exploitation status — kept in original order, capped at ~3
sentences. Journalists' lead paragraphs are already summaries, so this stays
close to LLM-quality without any API key. Badges, affected versions, priority
labels, and CVE cross-references are extracted with deterministic rules
(`scripts/enrich.py`). Set `VULNWIRE_FETCH_ARTICLES=false` to skip full-text
fetching and fall back to RSS summaries only.

## Data sources

**Structured vulnerability data:** CISA KEV catalog (confirmed exploitation),
NVD CVE API (CVSS/descriptions), FIRST EPSS full daily snapshot (predicted
exploitation).

**News media (RSS):** The Hacker News, BleepingComputer, Krebs on Security,
Dark Reading, SecurityWeek, The Record, Insurance Journal, Reinsurance News.

**Vendor / first-party research (RSS, tagged RESEARCH):** Rapid7, Tenable,
Wiz, Unit 42 (Palo Alto), Cisco Talos, Google Project Zero, Check Point
Research, SentinelOne Labs, Qualys, Microsoft MSRC, watchTowr Labs, Horizon3
Attack Research, ZDI Published Advisories.

**Government / community advisories (RSS, tagged ADVISORY):** CISA
Advisories, SANS ISC.

All via published RSS/APIs — syndication, not scraping. Every feed fails
soft: a dead URL logs a warning and contributes zero items. Each run embeds
a `feed_health` map (feed name → item count) in `news.json`, and the Actions
log warns about feeds returning zero, so dead or renamed feed URLs are easy
to spot and fix in the `FEEDS` list.

## Scope (read before extending)

- **Public sources only:** CISA KEV, NVD, public security/insurance RSS.
  Nothing references any organization's assets, hostnames, clients, or
  internal environment.
- **Cyber Insurance = industry news**, never anyone's book of business.
- **Query guidance, not query strings:** Tanium/Rapid7 hints are best-practice
  patterns; you write your own queries in your own tooling.

## How it works

```
CISA KEV + NVD              Security + Insurance RSS
      │                              │
      ▼                              ▼
scripts/collect_intel.py    scripts/collect_news.py    (4x daily via Actions)
      │                              │
      └── scripts/guidance.py + scripts/enrich.py ──┐
      │                              │              │
      ▼                              ▼              │
 data/intel.json              data/news.json  ◄─────┘
      └──────────────┬───────────────┘
                     ▼
        index.html (GitHub Pages) — tabs, badges, CVE tracker, search
```

- `scripts/collect_intel.py` — CISA KEV + optional NVD enrichment, transparent
  priority scoring, badges/impact, product-aware hints.
- `scripts/collect_news.py` — RSS ingestion, category classification (with an
  insurance-domain guard), full-text fetch, extractive analysis, badges,
  impact, CVE extraction, hints.
- `scripts/collect_epss_movers.py` — full-snapshot EPSS diffing to catch
  pre-KEV, pre-press exploitation surges.
- `scripts/enrich.py` — free analysis synthesis, badge/impact/CVE extraction,
  EPSS batch fetching, and the unified KEV+EPSS+CVSS priority scorer.
- `scripts/guidance.py` — product/CVE/port extraction and Tanium/Rapid7 hint
  construction; knows appliances, browser extensions, and mobile apps aren't
  standard endpoints. Extend `KNOWN_PRODUCTS` to recognize more vendors.
- `index.html` — renders everything client-side. All fetched text goes
  through `textContent`/DOM APIs (no `innerHTML`) to avoid injection.

## Update cycle

The workflow runs 4x daily, anchored to **EDT**: 8:00 AM, 12:00 PM, 3:30 PM,
12:00 AM (cron `0 12`, `0 16`, `30 19`, `0 4` UTC). GitHub cron doesn't
follow daylight saving — in winter these fire one local hour later unless you
shift each hour +1. It can also be triggered manually from the Actions tab.

## Setup

1. Push to GitHub, enable **Pages** (repo root).
2. Optional free key: `NVD_API_KEY` repo secret (raises the NVD rate limit;
   request at nvd.nist.gov/developers/request-an-api-key). Nothing else needed.
3. **Settings → Actions → General → Workflow permissions:** Read and write.
4. Trigger the workflow manually once so `data/*.json` exist before Pages
   serves the page.

## Configuring feeds

Edit `FEEDS` in `scripts/collect_news.py`. **Verify each URL** — RSS paths
change. Category keywords live in `CATEGORY_KEYWORDS`; the insurance guard in
`INSURANCE_REQUIRED_TERMS`.

## Local testing

Collectors need outbound access to feed hosts (designed for Actions). To
preview the UI locally, serve over HTTP (not `file://`):

```
python3 -m http.server 8000   # then open http://localhost:8000
```

The included `data/*.json` are sample data; the first real run overwrites them.
