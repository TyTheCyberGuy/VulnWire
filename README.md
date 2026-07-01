# VulnWire

A static threat-intelligence digest, hosted on GitHub Pages, powered by a
scheduled GitHub Actions collector. No live backend, no environment data.

## Scope (read before extending)

- **Public sources only:** CISA KEV catalog + NVD CVE API. Nothing here ever
  references any specific organization's assets, hostnames, or internal
  environment.
- **Query guidance, not query strings:** the Tanium/Rapid7 fields are
  generic best-practice *patterns* for how to approach validating a class
  of vulnerability. They are intentionally not copy-paste-ready — you write
  your own queries by hand, in your own tooling, against your own
  environment.
- **AI enrichment is optional and constrained:** if enabled, the LLM is only
  used to phrase a plain-language summary of public CVE data. The prompt
  explicitly forbids inventing asset names or environment-specific detail.
  If no `OPENAI_API_KEY` secret is set, those fields are simply left null
  and the dashboard falls back to the raw KEV description.

## How it works

```
CISA KEV + NVD  --(daily cron via GitHub Actions)-->  collect_intel.py
                                                              │
                                                              ▼
                                                    data/intel.json
                                                              │
                                                              ▼
                                              index.html (GitHub Pages)
```

`collect_intel.py`:
1. Pulls the current CISA KEV catalog.
2. Optionally enriches each entry with CVSS data from NVD.
3. Applies a transparent, rule-based priority score (KEV status + known
   ransomware use + CVSS score — see `score_priority()`).
4. Tags each entry with generic vulnerability-class labels (e.g. "network
   edge", "unauthenticated rce") via keyword matching.
5. Attaches best-practice query guidance for that class from a small
   static library (`QUERY_GUIDANCE_LIBRARY`).
6. Optionally asks an LLM for a one-sentence plain-language summary.
7. Writes everything to `data/intel.json`.

`index.html` fetches `data/intel.json` client-side and renders it. It never
uses `innerHTML` on any fetched or AI-generated text — everything goes
through `textContent` / DOM APIs to avoid injection risk if a feed or
model output ever contains markup.

## Setup

1. Push this repo to GitHub, enable **Pages** (serve from the repo root or
   `/docs`, your choice — adjust paths if you move `index.html`).
2. (Optional) Add repo secrets under **Settings → Secrets and variables →
   Actions**:
   - `NVD_API_KEY` — raises the NVD rate limit; not required.
   - `OPENAI_API_KEY` — enables AI summary enrichment; not required.
3. The workflow (`.github/workflows/collect.yml`) runs daily at 12:00 UTC
   and can also be triggered manually from the Actions tab
   (`workflow_dispatch`).
4. First run: trigger it manually once so `data/intel.json` exists before
   Pages tries to serve it.

## Local testing

The collector needs outbound access to `cisa.gov` and `nvd.nist.gov`,
which most sandboxed dev environments won't allow — it's designed to run
in GitHub Actions, which has full internet access. To test the logic
locally without hitting those hosts, monkeypatch `fetch_kev` and
`fetch_nvd_details` with sample data before calling `main()`.
