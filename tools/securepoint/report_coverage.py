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
        # Link snippets to command roots. This is traceability, not an assertion
        # that every UI field has been manually verified on hardware.
        roots=sorted({o['group'] for o in ops if re.search(r'\b'+re.escape(o['group'])+r' (?:get|set|new|update|delete|status)\b',source)})
        direct=source_ops.get(p['url'],[])
        features.append(dict(title=title,url=p['url'],revision=p['revision'],operation_ids=direct,
                             referenced_command_groups=roots,
                             review_status='catalog_mapped' if direct else 'guide_retrieved',
                             live_verified=False))
    (ROOT / 'docs/securepoint/feature-matrix.json').write_text(json.dumps(features,indent=2,ensure_ascii=False)+'\n')
    states=collections.Counter(p['classification'] for p in manifest['pages'])
    verification_path=(ROOT / 'docs/securepoint/live-read-verification.json')
    live=json.loads(verification_path.read_text()) if verification_path.exists() else {}
    lines=['# Documentation coverage','',
           f"Research snapshot: {manifest['retrieved_at']}. Retrieved {len(manifest['pages'])} pages: "+', '.join(f'{n} {kind}' for kind,n in sorted(states.items()))+'.',
           '',f"The catalog contains {len(ops)} typed operations across {len(groups)} groups. {sum(bool(o.get('unavailable_reason')) for o in ops)} entries are unavailable because the vendor documentation does not establish usable 14.x syntax.",
           '', 'Retrieval, extraction, and live verification are separate statuses. All source text was fetched and scanned; core CLI grammar, parameter relationships, activation commands, and known malformed examples were reviewed during implementation. This does not establish complete GUI parity or live interoperability for every catalog entry.',
           '', 'The complete page inventory is in [wiki-manifest.json](wiki-manifest.json). [feature-matrix.json](feature-matrix.json) maps current guides and command references to catalog entries or records them as retrieved guides needing further reconciliation. Original wiki text and rendered HTML remain in the ignored local cache.',
           '', '| Command group | Typed operations |','| --- | ---: |']
    lines += [f'| `{g}` | {n} |' for g,n in sorted(groups.items())]
    lines += ['', '## Execution gaps','']
    lines += [f"- `{o['command']}`: {o['unavailable_reason']} ([source]({o['source']}))." for o in ops if o.get('unavailable_reason')]
    lines += ['', 'Interactive editors, undocumented internal setup commands, and arbitrary Linux shell commands are excluded. Template content is managed with `extc template set`; documented EXTC variables provide the appliance application configuration interface. Portal-owned configuration, hardware installation, hypervisor setup, and client-side VPN installation are outside the local appliance management interface.',
              '', '## Verification boundary','',
              (f"Read-only MCP verification on firmware {live.get('firmware')} passed {len(live.get('commands',[]))} command checks. The appliance advertises {live.get('advertised_commands')} commands in JSON session mode. Only exact read operations tested on that firmware are marked live-verified. No configuration write, firmware action, restore, file upload, or secret export was attempted." if live else 'No real appliance has been connected yet.'),
              '', 'Mutations require both `read_only=false` and `allow_unverified=true`; this is an explicit operator opt-in to documentation-derived behavior. All mutations remain live-unverified.',
              '', 'Before declaring full UTM management verified, resolve the unavailable schemas and the unmapped guide entries against a 14.x test appliance, exercise each operation family, and capture sanitized transcripts. There is no automatic claim of full support based on a matching help entry alone.','']
    (ROOT / 'docs/securepoint/coverage.md').write_text('\n'.join(lines))
    print(f'Wrote coverage report and {len(features)} current feature/reference entries')


if __name__=='__main__':main()
