# VulnWire

A static cybersecurity threat-intel feed, hosted on GitHub Pages, powered by
scheduled GitHub Actions collectors. No live backend, no environment data.

## What it shows

A tabbed card feed across categories:

- **Data Breaches** — breach/leak/exposure news
- **Ransomware** — ransomware and extortion news
- **Vulnerabilities** — vuln news + CVE items from CISA KEV
- **Cyber Insurance** — cyber insurance and insurance-brokerage industry news
  (coverage, underwriting, claims, regulatory action affecting insurers/brokers)
- **CVE Reports** — CISA KEV entries with CVSS + prioritization
- **History** — everything, newest first

Each card follows the same shape: headline, source, an **ANALYSIS** summary,
an optional **PROTOCOL RESPONSE** (best-practice defensive guidance), and a
link to the original article.

## Scope (read before extending)

- **Public sources only:** CISA KEV, NVD, and public security/insurance RSS
  feeds. Nothing here references any specific organization's assets,
  hostnames, clients, or internal environment.
- **Cyber Insurance = industry news**, not anyone's book of business. It
  tracks general insurer/broker cybersecurity developments, never internal
  or client-specific data.
- **Query guidance, not query strings:** CVE cards include generic
  best-practice *patterns* for approaching Tanium/Rapid7 validation — never
  copy-paste-ready queries. You write your own queries by hand.
- **AI enrichment is optional and constrained:** if enabled, the LLM only
  rephrases public data into an ANALYSIS/PROTOCOL RESPONSE. The prompt
  forbids inventing environment-specific detail. If `OPENAI_API_KEY` isn't
  set, ANALYSIS falls back to the article's own summary and PROTOCOL
  RESPONSE is left blank.

## How it works

```
CISA KEV + NVD          Security + Insurance RSS
      │                          │
      ▼                          ▼
collect_intel.py           collect_news.py     (daily via GitHub Actions)
      │                          │
      ▼                          ▼
 data/intel.json          data/news.json
      │                          │
      └────────────┬─────────────┘
                   ▼
          index.html (GitHub Pages) — loads both, tabs + filters client-side
```

- `collect_intel.py` — pulls CISA KEV, optionally enriches from NVD, applies a
  transparent rule-based priority score, tags vulnerability class, attaches
  query guidance.
- `collect_news.py` — pulls RSS feeds, classifies each article into one or
  more categories (with an extra guard so only genuine insurance-domain
  articles land in Cyber Insurance), optionally AI-enriches.
- `index.html` — fetches both JSON files, merges, and renders the tabbed
  card UI. Never uses `innerHTML` on fetched/AI text — everything goes
  through `textContent`/DOM APIs to avoid injection.

## Configuring feeds

Edit the `FEEDS` list at the top of `collect_news.py`. **Verify each URL** —
RSS paths change over time. Add or remove sources freely; keyword
classification runs on every article regardless of source. Category keywords
live in `CATEGORY_KEYWORDS` (and `INSURANCE_REQUIRED_TERMS` for the
insurance guard) in the same file.

## Setup

1. Push this repo to GitHub, enable **Pages** (serve from repo root).
2. (Optional) Add repo secrets under **Settings → Secrets and variables →
   Actions**:
   - `OPENAI_API_KEY` — enables AI ANALYSIS/PROTOCOL enrichment.
   - `NVD_API_KEY` — raises the NVD rate limit.
3. **Settings → Actions → General → Workflow permissions:** set to
   **Read and write** so the workflow can commit the refreshed JSON.
4. Trigger the workflow once manually (**Actions → Collect VulnWire Intel →
   Run workflow**) so `data/news.json` and `data/intel.json` exist before
   Pages serves the page.

## Local testing

The collectors need outbound access to the feed hosts, which sandboxed dev
environments often block — they're built to run in GitHub Actions. To preview
the UI locally, serve over HTTP (not `file://`, which blocks `fetch`):

```
python3 -m http.server 8000
# then open http://localhost:8000
```

The included `data/*.json` are **sample data** for previewing the UI. The
first real workflow run overwrites them.
