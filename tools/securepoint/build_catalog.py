#!/usr/bin/env python3
"""Extract structured CLI tables and apply reviewed semantic overrides.

Run research_wiki.py first. This does not execute commands on an appliance.
Generated schemas are documentation-derived, not live interoperability claims.
"""
import concurrent.futures
import html
from html.parser import HTMLParser
import json
import pathlib
import re
import sys
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from research_wiki import api, CACHE

ROOT = pathlib.Path(__file__).resolve().parents[2]

ROOTS = set("alertingcenter appmgmt captiveportal cert clientlessvpn cluster debug dhcp dns extc geolocation interface ipsec mail manager node object openvpn pkey qos route rproxy rsa rule server service spf2bd ssh syslog system usc_vhost user view webfilter wireguard wlan".split())


class Cell:
    def __init__(self, attrs):
        self.attrs = dict(attrs)
        self.text = []
        self.headings = []
        self.code = []

    def value(self):
        return re.sub(r"\s+", " ", "".join(self.text)).strip()


class Tables(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tables, self.table, self.row, self.cell = [], None, None, None
        self.level, self.heading, self.code_depth, self.code_text = 0, None, 0, []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "table":
            self.level += 1
            if self.level == 1:
                self.table = []
        if self.level != 1:
            return
        if tag == "tr":
            self.row = []
        if tag in ("td", "th"):
            self.cell = Cell(attrs)
        if self.cell is not None:
            if tag in ("style", "script"):
                self.skip += 1
            if tag in ("br", "p", "li", "div"):
                self.cell.text.append(" ")
            if re.fullmatch(r"h[1-6]", tag):
                self.heading = []
            if tag == "pre" or "code" in a.get("class", "").split():
                if not self.code_depth:
                    self.code_text = []
                self.code_depth += 1
            elif self.code_depth:
                self.code_depth += 1

    def handle_endtag(self, tag):
        if self.level == 1:
            if self.cell is not None:
                if tag in ("style", "script") and self.skip:
                    self.skip -= 1
                if re.fullmatch(r"h[1-6]", tag) and self.heading is not None:
                    self.cell.headings.append("".join(self.heading).strip())
                    self.heading = None
                if self.code_depth:
                    self.code_depth -= 1
                    if not self.code_depth:
                        self.cell.code.append("".join(self.code_text))
            if tag in ("td", "th") and self.cell is not None:
                self.row.append(self.cell)
                self.cell = None
            if tag == "tr" and self.row is not None:
                self.table.append(self.row)
                self.row = None
            if tag == "table":
                self.tables.append(self.table)
                self.table = None
        if tag == "table":
            self.level -= 1

    def handle_data(self, data):
        if self.cell is not None and not self.skip:
            self.cell.text.append(data)
            if self.heading is not None:
                self.heading.append(data)
            if self.code_depth:
                self.code_text.append(data)


def expand(rows):
    spans = {}
    for cells in rows:
        row, col = [], 0
        for cell in cells:
            while col in spans:
                row.append(spans[col][0]); col += 1
            row.append(cell)
            n = int(cell.attrs.get("rowspan", 1))
            if n > 1:
                spans[col] = (cell, n)
            col += 1
        while col in spans:
            row.append(spans[col][0]); col += 1
        yield row
        spans = {k: (v, n - 1) for k, (v, n) in spans.items() if n > 1}


def command(cell):
    candidates = cell.headings[::-1] + [cell.value()]
    for text in candidates:
        text = text.lower().strip()
        text = re.sub(r"^(?:cli>|cli›)\s*", "", text)
        m = re.match(r"([a-z_][a-z_0-9]*(?: [a-z_][a-z_0-9]*){0,5})", text)
        if not m:
            continue
        words = m[1].split()
        if words[0] not in ROOTS:
            continue
        # Visible command text sometimes repeats the hidden heading.
        for i in range(1, len(words)):
            if i >= 2 and len(words) == i * 2 and words[i:] == words[:i]:
                words = words[:i]
                break
        return " ".join(words)


def extract(title, revision):
    path = CACHE / (str(revision["page_id"]) + ".html")
    if not path.exists():
        data = api(action="parse", oldid=revision["revision"], prop="text", uselang="en")
        path.write_text(data["parse"]["text"]["*"], encoding="utf-8")
    parser = Tables()
    parser.feed(path.read_text())
    result = []
    for table in parser.tables:
        if not table:
            continue
        header = [c.value().lower() for c in table[0]]
        if not any(x in " ".join(header) for x in ("command", "befehl")):
            continue
        has_param = any("parameter" in x for x in header)
        current, previous = None, None
        for row in list(expand(table))[1:]:
            if len(row) < 2:
                continue
            if row[0] is not previous:
                cmd = command(row[0])
                previous = row[0]
                current = None
                if not cmd:
                    continue
                desc = row[2 if has_param and len(row) > 2 else 1].value()
                examples = [s for c in row[3 if has_param else 2:] for s in c.code]
                current = dict(command=cmd, description=desc[:600], parameters=[], examples=examples,
                               source=revision["url"], revision=revision["revision"])
                result.append(current)
            if current is None or not has_param or len(row) < 3:
                continue
            name = row[1].value()
            m = re.fullmatch(r"([a-z_][a-z_0-9-]*)(?:\s+\(.*\)|\s+.*)?", name)
            if m and len(name.split()) <= 8:
                key = m[1]
                if key not in {p['name'] for p in current['parameters']}:
                    current['parameters'].append(dict(name=key, description=row[2].value()[:400]))
    return result


def main():
    manifest = json.loads((ROOT / "docs/securepoint/wiki-manifest.json").read_text())["pages"]
    pages = [p for p in manifest if p["classification"] == "current" and
             (p["title"].startswith("UTM/CLI/") or p["title"] in ("CLI/Cert", "UTM/EXTRAS/CLI/view"))]
    operations = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for p, ops in zip(pages, pool.map(lambda p: extract(p["title"], p), pages)):
            for op in ops:
                if op['command'] not in operations or len(op['parameters']) > len(operations[op['command']]['parameters']):
                    operations[op['command']] = op
            print(p["title"], len(ops), flush=True)
    path = (ROOT / ".cache/securepoint/extracted-operations.json")
    path.write_text(json.dumps(list(operations.values()), ensure_ascii=False, indent=2) + "\n")
    print(f"Extracted {len(operations)} command entries to {path}; run finalize_catalog.py next")


if __name__ == '__main__':
    main()
