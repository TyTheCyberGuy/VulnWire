#!/usr/bin/env python3
"""
build_feed.py — merges news, CVE intel, and EPSS movers into one unified,
machine-readable endpoint: data/feed.json

This is the integration surface for downstream consumers (IR dashboards,
SOAR playbooks, chat-ops bots). It is intentionally stable:
- schema_version bumps on any breaking change
- every item carries: id, type, title, url, published, categories,
  severity/exploitation badges, structured advisory (w5h), impact_type,
  threat_actors, cve_ids, and source attribution
- sorted newest-first

Consume it at: https://<user>.github.io/<repo>/data/feed.json
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

FEED_SCHEMA = "1.0"
OUT = Path("data/feed.json")
SOURCES = [Path("data/news.json"), Path("data/intel.json"), Path("data/movers.json")]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vulnwire-feed")


def load(path: Path) -> list[dict]:
    try:
        return json.loads(path.read_text()).get("items", [])
    except (OSError, json.JSONDecodeError):
        log.warning("Could not load %s — skipping", path)
        return []


def normalize(item: dict) -> dict:
    """Intel items use cve_id as id and sources[] for url; flatten to the
    common shape so consumers handle exactly one schema."""
    out = dict(item)
    if "id" not in out and out.get("cve_id"):
        out["id"] = out["cve_id"]
    if "url" not in out and out.get("sources"):
        nvd = next((s["url"] for s in out["sources"] if s.get("name") == "NVD"), None)
        out["url"] = nvd or out["sources"][0].get("url")
    if "source" not in out and out.get("sources"):
        out["source"] = out["sources"][0].get("name", "Unknown")
    out.setdefault("categories", ["vulnerabilities"])
    if "published" not in out:
        out["published"] = out.get("date_added_to_kev") or out.get("first_seen")
    return out


def main() -> None:
    items, seen = [], set()
    for path in SOURCES:
        for raw in load(path):
            item = normalize(raw)
            key = item.get("id") or item.get("title")
            if key in seen:
                continue
            seen.add(key)
            items.append(item)

    items.sort(key=lambda i: i.get("published") or "", reverse=True)

    OUT.write_text(json.dumps({
        "schema_version": FEED_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "item_count": len(items),
        "items": items,
    }, indent=2))
    log.info("Unified feed: %d items -> %s", len(items), OUT)


if __name__ == "__main__":
    main()
