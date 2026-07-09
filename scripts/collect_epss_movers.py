#!/usr/bin/env python3
"""
collect_epss_movers.py — detects old/quiet CVEs "waking up" via EPSS surges.

Why this exists: an old CVE (say, a medium-severity 2014 flaw) that starts
being exploited will eventually reach CISA KEV and the security press — but
EPSS often moves first. FIRST.org publishes a full daily snapshot of EPSS
scores for every CVE (free CSV, no key). This script diffs today's snapshot
against the previous run's state and flags CVEs whose exploitation
probability surged, then enriches the top movers from NVD.

Outputs:
- data/movers.json      — the surge items rendered by the dashboard
- data/epss_state.json  — compact score snapshot (only scores >= floor,
                          rounded) used as the diff baseline for next run

First run behavior: no previous state -> writes the baseline and reports
zero movers. Surges appear from the second run onward.
"""

import csv
import gzip
import io
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

import enrich
import guidance
from collect_intel import extract_cvss, fetch_nvd_details

EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
STATE_PATH = Path("data/epss_state.json")
OUTPUT_PATH = Path("data/movers.json")

# Only track scores >= this in the state file (keeps the repo small; scores
# below it are treated as ~0 when diffing).
STATE_FLOOR = float(os.environ.get("VULNWIRE_EPSS_STATE_FLOOR", "0.10"))
# A CVE is a "mover" if its score rose by SURGE_DELTA, or crossed SURGE_LEVEL.
SURGE_DELTA = float(os.environ.get("VULNWIRE_EPSS_SURGE_DELTA", "0.20"))
SURGE_LEVEL = float(os.environ.get("VULNWIRE_EPSS_SURGE_LEVEL", "0.50"))
# Ignore noise at very low absolute scores.
MIN_SCORE = float(os.environ.get("VULNWIRE_EPSS_MIN_SCORE", "0.35"))
MAX_MOVERS = int(os.environ.get("VULNWIRE_MAX_MOVERS", "10"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vulnwire-epss")


def fetch_epss_snapshot() -> dict:
    """Full daily EPSS snapshot: {CVE-ID: (score, percentile)}."""
    log.info("Downloading full EPSS snapshot...")
    resp = requests.get(EPSS_CSV_URL, timeout=60)
    resp.raise_for_status()
    text = gzip.decompress(resp.content).decode("utf-8", errors="replace")
    out = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#") or row[0] == "cve":
            continue
        try:
            out[row[0].upper()] = (float(row[1]), float(row[2]))
        except (IndexError, ValueError):
            continue
    log.info("Snapshot contains %d CVEs", len(out))
    return out


def load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(snapshot: dict) -> None:
    compact = {cve: round(vals[0], 3) for cve, vals in snapshot.items() if vals[0] >= STATE_FLOOR}
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(compact, separators=(",", ":")))
    log.info("Saved EPSS state: %d CVEs >= %.2f", len(compact), STATE_FLOOR)


def find_movers(snapshot: dict, previous: dict) -> list[dict]:
    movers = []
    for cve, (score, pct) in snapshot.items():
        if score < MIN_SCORE:
            continue
        old = previous.get(cve, 0.0)
        delta = score - old
        crossed = score >= SURGE_LEVEL and old < SURGE_LEVEL
        if delta >= SURGE_DELTA or crossed:
            movers.append({"cve_id": cve, "score": round(score, 3),
                           "previous": round(old, 3), "delta": round(delta, 3),
                           "percentile": round(pct, 3)})
    movers.sort(key=lambda m: m["delta"], reverse=True)
    return movers[:MAX_MOVERS]


def nvd_description(nvd_cve: dict | None) -> str:
    if not nvd_cve:
        return ""
    for d in nvd_cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def build_mover_item(m: dict, now_iso: str) -> dict:
    cve_id = m["cve_id"]
    nvd_cve = fetch_nvd_details(cve_id)
    desc = nvd_description(nvd_cve) or f"{cve_id} shows a sharp rise in EPSS exploitation probability."
    cvss = extract_cvss(nvd_cve)
    targets = guidance.extract_targets(desc)
    priority = enrich.unified_priority(kev=False, ransomware=False,
                                       cvss=cvss["cvss_v3_score"], epss=m["score"])
    year = cve_id.split("-")[1] if "-" in cve_id else "?"
    analysis = (
        f"EPSS exploitation probability for {cve_id} surged from "
        f"{m['previous']:.0%} to {m['score']:.0%} (percentile {m['percentile']:.0%}), "
        f"indicating a significant increase in predicted or observed exploitation "
        f"activity for this {year}-era vulnerability. It is not (yet) in CISA KEV — "
        f"this signal typically precedes KEV listing and press coverage. {desc}"
    )
    w5h = enrich.extract_w5h(f"EPSS Surge: {cve_id}", desc, {
        "active_exploitation": False, "epss_score": m["score"],
        "cvss_score": cvss["cvss_v3_score"],
    }, targets, None, now_iso)
    return {
        "cve_id": cve_id,
        "type": "epss_mover",
        "title": f"EPSS Surge: {cve_id}" + (f" ({targets['product']})" if targets.get("product") else ""),
        "source": "FIRST EPSS",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "published": now_iso,
        "first_seen": now_iso,
        "categories": ["vulnerabilities"],
        "analysis": analysis,
        "description": desc,
        "severity": cvss,
        "epss": {"score": m["score"], "previous": m["previous"],
                 "delta": m["delta"], "percentile": m["percentile"]},
        "priority": priority,
        "badges": {
            "active_exploitation": False,
            "epss_surge": True,
            "cvss_score": cvss["cvss_v3_score"],
            "cvss_rating": cvss["rating"],
            "epss_score": m["score"],
            "priority_label": priority["priority_label"],
        },
        "impact": enrich.extract_impact(desc, targets.get("product"),
                                        targets.get("is_appliance", False), targets.get("special")),
        "w5h": w5h,
        "impact_type": enrich.classify_impact(desc),
        "threat_actors": enrich.extract_threat_actors(desc),
        "cve_ids": [cve_id],
        "sources": [
            {"name": "FIRST EPSS", "url": "https://www.first.org/epss/"},
            {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
        ],
    }


def main() -> None:
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat(timespec="seconds")

    snapshot = fetch_epss_snapshot()
    previous = load_state()

    if not previous:
        log.info("No previous EPSS state — writing baseline, zero movers this run.")
        save_state(snapshot)
        OUTPUT_PATH.write_text(json.dumps({
            "schema_version": "1.0", "generated_at": now_iso,
            "note": "baseline run — surges appear from the next run onward",
            "item_count": 0, "items": [],
        }, indent=2))
        return

    movers = find_movers(snapshot, previous)
    log.info("Found %d EPSS movers (delta >= %.2f or crossed %.2f)",
             len(movers), SURGE_DELTA, SURGE_LEVEL)

    items = [build_mover_item(m, now_iso) for m in movers]

    OUTPUT_PATH.write_text(json.dumps({
        "schema_version": "1.0", "generated_at": now_iso,
        "item_count": len(items), "items": items,
    }, indent=2))
    save_state(snapshot)
    log.info("Wrote %d mover items to %s", len(items), OUTPUT_PATH)


if __name__ == "__main__":
    main()
