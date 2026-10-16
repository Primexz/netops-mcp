#!/usr/bin/env python3
"""Read the complete UTM wiki inventory; cache source locally, publish metadata only.

Uses only the Python standard library. Run from the repository root. Cached source
is deliberately not redistributed. The manifest records revisions and retrieval
failures so inaccessible documentation cannot silently count as reviewed.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import pathlib
import re
import time
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]

BASE = "https://wiki.securepoint.de/api.php"
CACHE = (ROOT / ".cache/securepoint/wiki")


def api(**params):
    url = BASE + "?" + urllib.parse.urlencode({"format": "json", **params})
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sp-utm-mcp-documentation-research/0.1"})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.load(response)
            if "error" in data:
                raise ValueError(data["error"])
            return data
        except Exception:
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def inventory():
    pages = []
    params = dict(action="query", list="allpages", apprefix="UTM/", aplimit=500)
    while True:
        data = api(**params)
        pages.extend(data["query"]["allpages"])
        if "continue" not in data:
            break
        params.update(data["continue"])
    # The CLI overview links certificate commands outside the UTM prefix.
    extra = api(action="query", titles="UTM|CLI/Cert|CLI/Cert.lang", redirects=1)
    pages.extend(p for p in extra["query"]["pages"].values() if "missing" not in p)
    return sorted({p["pageid"]: p for p in pages}.values(), key=lambda p: p["title"])


def fetch(batch):
    ids = "|".join(str(p["pageid"]) for p in batch)
    try:
        data = api(action="query", pageids=ids, prop="revisions", rvprop="content|ids|timestamp", rvslots="main")
        results = []
        for page in data["query"]["pages"].values():
            CACHE.mkdir(parents=True, exist_ok=True)
            path = CACHE / (str(page["pageid"]) + ".json")
            path.write_text(json.dumps(page, ensure_ascii=False), encoding="utf-8")
            results.append(page)
        return results
    except Exception as exc:
        if len(batch) > 1:
            return [p for item in batch for p in fetch([item])]
        return [{**batch[0], "retrieval_error": str(exc)}]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    pages = inventory()
    cached, pending = [], []
    for page in pages:
        path = CACHE / (str(page["pageid"]) + ".json")
        if path.exists() and not args.refresh:
            cached.append(json.loads(path.read_text()))
        else:
            pending.append(page)
    batches = [pending[i:i + 25] for i in range(0, len(pending), 25)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for result in pool.map(fetch, batches):
            cached.extend(result)
            print(f"Retrieved {len(cached)}/{len(pages)} pages", flush=True)
    manifest = []
    for page in sorted(cached, key=lambda p: p["title"]):
        rev = page.get("revisions", [{}])[0]
        text = rev.get("slots", {}).get("main", {}).get("*", "")
        title = page["title"]
        links = sorted(set(re.findall(r"\[\[([^\]|#]+)", text)))
        manifest.append(dict(title=title, page_id=page["pageid"], revision=rev.get("revid"),
                             timestamp=rev.get("timestamp"), sha256=hashlib.sha256(text.encode()).hexdigest(),
                             url="https://wiki.securepoint.de/index.php?" + urllib.parse.urlencode({"title": title, "oldid": rev.get("revid", "")}),
                             classification="translation" if title.endswith(".lang") else "archive" if re.search(r" v\.?\d| \d{1,2}\.\d| V\d", title) else "current",
                             linked_pages=links, retrieval_error=page.get("retrieval_error")))
    out = (ROOT / "docs/securepoint/wiki-manifest.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(retrieved_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                   pages=manifest), ensure_ascii=False, indent=2) + "\n")
    print(f"Wrote {out}: {len(manifest)} pages, {sum(bool(p['retrieval_error']) for p in manifest)} failures")


if __name__ == "__main__":
    main()
