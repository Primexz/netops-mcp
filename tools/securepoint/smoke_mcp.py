#!/usr/bin/env python3
"""Exercise the built stdio server. --live runs only a fixed read-only allowlist.

No passwords are accepted on the command line. Live results record only protocol
status, firmware, operation names, and row counts, never appliance configuration.
"""
import argparse
import datetime
import json
import pathlib
import select
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]

READS = [
    'system info','node get','node group get','service get','service group get',
    'rule get','rule group get','rule timeprofile get','interface get',
    'interface zone get','interface address get','route get','dns get',
    'ipsec status','openvpn status','wireguard interface get','appmgmt get',
    'system config get','extc application get',
    'dhcp pool get','dhcp lease get','dhcp lease list','webfilter rule get',
    'webfilter ruleset get','oauth get','ctproxy status','dns filter get',
]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary',default=str(ROOT / 'bin/sp-utm-mcp'))
    ap.add_argument('--config',default=str(ROOT / '.local/sp-utm.toml'))
    ap.add_argument('--profile',default='headquarters')
    ap.add_argument('--live',action='store_true')
    args=ap.parse_args()
    process=subprocess.Popen([args.binary,'--config',args.config,'--transport','stdio'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
    seq=0
    def send(method,params=None,notification=False):
        nonlocal seq
        seq+=1
        request=dict(jsonrpc='2.0',method=method,params=params or {})
        if not notification:request['id']=seq
        process.stdin.write(json.dumps(request)+'\n');process.stdin.flush()
        if notification:return
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            ready,_,_=select.select([process.stdout],[],[],max(0,deadline-time.monotonic()))
            if not ready:break
            line=process.stdout.readline()
            if not line:raise RuntimeError('server closed stdout')
            response=json.loads(line) # Any non-JSON stdout makes the smoke test fail.
            if response.get('id')==seq:
                if 'error' in response:raise RuntimeError('MCP protocol error: '+str(response['error'].get('message')))
                return response['result']
        raise TimeoutError('MCP response timeout')
    def tool(name,arguments):
        r=send('tools/call',dict(name=name,arguments=arguments))
        if r.get('isError'):return None, next((x.get('text','') for x in r.get('content',[]) if x.get('type')=='text'),'tool error')
        return r.get('structuredContent'),None
    try:
        initialize=send('initialize',dict(protocolVersion='2025-06-18',capabilities={},clientInfo=dict(name='securepoint-smoke',version='1')))
        send('notifications/initialized',notification=True)
        listing=send('tools/list')
        profiles,error=tool('utm_profiles_list',{})
        if error:raise RuntimeError(error)
        report=dict(protocol=initialize['protocolVersion'],tool_count=len(listing['tools']),profiles=len(profiles['profiles']),
                    checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),commands=[],results=[],writes_attempted=0)
        if args.live:
            cap,error=tool('utm_appliance_discover',dict(profile=args.profile))
            if error:raise RuntimeError(error)
            report['firmware']=cap['firmware'];report['advertised_commands']=len(cap.get('commands',[]))
            print('Firmware:',cap['firmware'],'advertised commands:',report['advertised_commands'],flush=True)
            for cmd in READS:
                data,error=tool('utm_'+cmd.replace(' ','_'),dict(profile=args.profile,limit=5))
                result=dict(command=cmd,success=error is None)
                if error:result['error']=error
                else:
                    output=data.get('output',{});result.update(format=output.get('format'),total=output.get('total'))
                    report['commands'].append(cmd)
                report['results'].append(result)
                print(cmd, 'OK' if not error else 'FAILED: '+error,flush=True)
            path=(ROOT / 'docs/securepoint/live-read-verification.json')
        else:path=(ROOT / '.cache/securepoint/stdio-smoke.json')
        path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(report,indent=2)+'\n')
        print('Stdio protocol OK;',report['tool_count'],'tools;',report['writes_attempted'],'writes; report:',path)
        if any(not r['success'] for r in report['results']):raise RuntimeError('one or more live read checks failed')
    finally:
        if process.stdin:process.stdin.close()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)


if __name__=='__main__':main()
