#!/usr/bin/env python3
"""Import command grammar from a read-only `spcli help` capture.

Only command names, syntax, and firmware provenance are retained. The output
contains no configuration values or appliance identity. Review before committing.
"""
import argparse
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('capture',type=pathlib.Path)
    ap.add_argument('--firmware',required=True)
    args=ap.parse_args()
    commands=[]
    for block in re.split(r'^Command: ',args.capture.read_text(),flags=re.M)[1:]:
        lines=block.splitlines();command=lines[0].strip()
        usage=next((line.strip()[7:] for line in lines if line.strip().startswith('Usage: ')),'')
        # Include continued syntax lines for older hand-written commands.
        additional=[]
        for line in lines[3:]:
            if re.match(r'^\s*\[?\s*[a-z_][a-z0-9_-]*\s+<[^>]+>',line):additional.append(line.strip())
        commands.append(dict(command=command,usage=usage,additional_syntax=additional))
    output=dict(firmware=args.firmware,provenance='Securepoint built-in spcli help; read-only observation',commands=commands)
    (ROOT / 'docs/securepoint/appliance-command-schema.json').write_text(json.dumps(output,indent=2)+'\n')
    print('Imported',len(commands),'command signatures; no appliance identity or configuration values retained')


if __name__=='__main__':main()
