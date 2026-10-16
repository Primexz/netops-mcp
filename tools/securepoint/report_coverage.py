#!/usr/bin/env python3
"""Reconcile fetched UTM documentation and CLI catalog into reviewable reports."""
import collections
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    manifest = json.loads((ROOT / 'docs/securepoint/wiki-manifest.json').read_text())
    ops = json.loads((ROOT / 'internal/securepoint/catalog/operations.json').read_text())
    groups = collections.Counter(o['group'] for o in ops)
    source_ops = collections.defaultdict(list)
    for o in ops:
        source_ops[o['source']].append(o['id'])
    features = []
    for p in manifest['pages']:
        if p['classification']!='current':continue
        title=p['title']
        if not (title.startswith(('UTM/APP/','UTM/AUTH/','UTM/NET/','UTM/RULE/','UTM/VPN/','UTM/CLI/','UTM/CONFIG/','UTM/EXTRAS/')) or title in ('UTM/Administration','CLI/Cert')):continue
        cache=(ROOT / '.cache/securepoint/wiki')/(str(p['page_id'])+'.json')
        data=json.loads(cache.read_text())
        source=data.get('revisions',[{}])[0].get('slots',{}).get('main',{}).get('*','')
        source=re.sub(r'<!--.*?-->','',source,flags=re.S)
        # Link guide snippets to the documented command roots for traceability.
        roots=sorted({o['group'] for o in ops if re.search(r'\b'+re.escape(o['group'])+r' (?:get|set|new|update|delete|status)\b',source)})
        direct=source_ops.get(p['url'],[])
        features.append(dict(title=title,url=p['url'],revision=p['revision'],operation_ids=direct,
                             referenced_command_groups=roots,
                             review_status='catalog_mapped' if direct else 'guide_retrieved'))
    (ROOT / 'docs/securepoint/feature-matrix.json').write_text(json.dumps(features,indent=2,ensure_ascii=False)+'\n')
    states=collections.Counter(p['classification'] for p in manifest['pages'])
    lines=['# Documentation coverage','',
           f"Research snapshot: {manifest['retrieved_at']}. Retrieved {len(manifest['pages'])} pages: "+', '.join(f'{n} {kind}' for kind,n in sorted(states.items()))+'.',
           '',f"The catalog contains {len(ops)} typed operations across {len(groups)} groups. {sum(bool(o.get('unavailable_reason')) for o in ops)} entries are unavailable because the vendor documentation does not establish usable 14.x syntax.",
           '', 'The vendor wiki is the source of support for catalog operations. All source text was fetched and scanned; core CLI grammar, parameter relationships, activation commands, and known malformed examples were reviewed during implementation. Entries with incomplete or obsolete syntax remain unavailable.',
           '', 'The complete page inventory is in [wiki-manifest.json](wiki-manifest.json). [feature-matrix.json](feature-matrix.json) maps current guides and command references to catalog entries or records them as retrieved guides needing further reconciliation. Original wiki text and rendered HTML remain in the ignored local cache.',
           '', '| Command group | Typed operations |','| --- | ---: |']
    lines += [f'| `{g}` | {n} |' for g,n in sorted(groups.items())]
    lines += ['', '## Execution gaps','']
    lines += [f"- `{o['command']}`: {o['unavailable_reason']} ([source]({o['source']}))." for o in ops if o.get('unavailable_reason')]
    lines += ['', 'Interactive editors, undocumented internal setup commands, and arbitrary Linux shell commands are excluded. Template content is managed with `extc template set`; documented EXTC variables provide the appliance application configuration interface. Portal-owned configuration, hardware installation, hypervisor setup, and client-side VPN installation are outside the local appliance management interface.',
              '', '## Catalog policy','',
              'Catalog operations and parameter schemas are based on the vendor wiki. Configuration changes require `read_only=false`, plan execution, and any applicable lifecycle or sensitive-data permissions. Documentation gaps remain explicit in the catalog and coverage report.','']
    (ROOT / 'docs/securepoint/coverage.md').write_text('\n'.join(lines))
    print(f'Wrote coverage report and {len(features)} current feature/reference entries')


if __name__=='__main__':main()
