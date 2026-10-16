#!/usr/bin/env python3
"""Check MCP over HTTP without connecting to or changing any appliance.

Reads the bearer token from an environment variable. Checks initialization,
tool discovery, and configured profile metadata; never prints credentials.
"""
import argparse
import json
import os
import urllib.request


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--url',default='http://127.0.0.1:8080/mcp')
    ap.add_argument('--token-env',default='SP_UTM_MCP_HTTP_TOKEN')
    args=ap.parse_args()
    token=os.environ.get(args.token_env)
    if not token:raise SystemExit(args.token_env+' is not set')
    version='2025-11-25'
    seq=0
    def request(method,params,notification=False):
        nonlocal seq
        seq+=1
        body=dict(jsonrpc='2.0',method=method,params=params)
        if not notification:body['id']=seq
        req=urllib.request.Request(args.url,data=json.dumps(body).encode(),headers={
            'Authorization':'Bearer '+token,'Content-Type':'application/json',
            'Accept':'application/json, text/event-stream','MCP-Protocol-Version':version,
        })
        with urllib.request.urlopen(req,timeout=15) as response:
            if notification:
                if response.status!=202:raise RuntimeError('notification was not accepted')
                return
            data=json.load(response)
        if data.get('id')!=seq or 'error' in data:raise RuntimeError('MCP protocol check failed')
        return data['result']
    initialized=request('initialize',dict(protocolVersion=version,capabilities={},clientInfo=dict(name='securepoint-http-smoke',version='1')))
    version=initialized['protocolVersion']
    request('notifications/initialized',{},notification=True)
    tools=request('tools/list',{})
    profiles=request('tools/call',dict(name='utm_profiles_list',arguments={}))
    if profiles.get('isError'):raise RuntimeError('profile query failed')
    print('HTTP MCP OK:',len(tools['tools']),'tools,',len(profiles['structuredContent']['profiles']),'profiles; no appliance calls or writes.')


if __name__=='__main__':main()
