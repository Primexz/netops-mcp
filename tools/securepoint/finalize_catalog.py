#!/usr/bin/env python3
"""Build the embedded catalog with explicit corrections to vendor examples.

Parameter types describe CLI values, not appliance storage types. IDs and numeric
CLI tokens accept strings or numbers; arrays remain arrays. Unknown syntax is
recorded as a gap rather than exposed as an arbitrary-command escape hatch.
"""
import copy
import json
import pathlib
import re
import shlex

ROOT = pathlib.Path(__file__).resolve().parents[2]

RENAME = {
    "alertingcenter collectd": "alertingcenter collectd get",
    "alertingcenter syslog": "alertingcenter syslog pattern get",
    "alertingcenter severity": "alertingcenter severity get",
    "alertingcenter alerts": "alertingcenter alerts get",
    "alertingcenter report": "alertingcenter report create",
    "manager new hostlist": "manager new", "manager set hostlist": "manager set",
    "interface mobile sim": "interface mobile sim sendpin",
    "interface mobile modem": "interface mobile modem get",
    "interface mobile bearer": "interface mobile bearer get",
    "cluster maintainance set value": "cluster maintainance set",
    "rule implied group get": "rule implied group set",
    "rule implied rule get": "rule implied rule set",
}
REMOVE = {
    "system config save name", "extc value get application", "extc value set application",
    "system sysctl new name net", "system config setup", "cert parse", "extc template edit",
    "system upgrade confirm", "system upgrade privacy", "rule implied rule set implied_group",
}
ARRAYS = set("flags nodes services groups permission zones options hosts subnets push_subnets variables peer_address_list peer_interface_name_list peer_interface_id_list peer_id_list rcpts".split())
READ_TAILS = set("get list status info specs features defaults default getdiff get_with_state get_old_list get_sys_list get_db_list get_available dump lsgroups testjoin who check checkotp hint updatehint updatelatestcheck senders recipients count preview".split())
EXPLICIT_READ = {"object get", "system lsrrd", "system interface info", "debug show validators", "view webuser", "view supportuser", "system contentfilter categorize", "system ciphers", "system tools ping", "system tools traceroute", "system tools route", "system tools host", "wireguard ping", "syslog get", "mail stats users", "system remote get cur", "system remote get old", "system remote get new"}
SENSITIVE_OUTPUT = {"cert export privatekey", "cert export pkcs12", "pkey export", "rsa export", "openvpn export", "wireguard export", "system config export", "system config xmlreport", "system supportinfo", "system config otpexport", "mail archive content get", "mail archive preview"}
DISRUPTIVE = {"system reboot", "system poweroff", "system config factorysettings", "system config load", "system config load_dryrun", "system config import", "system config set", "system cloudbackup restore", "cluster maintainance set", "system predictable_interface_names", "system generate sshdkeys", "system generate webservercert", "mail archive resend", "mail queue flush"}


def main():
    entries = json.loads((ROOT / '.cache/securepoint/extracted-operations.json').read_text())
    ops, gaps = {}, []
    for o in entries:
        old = o['command']
        if old in REMOVE:
            gaps.append(dict(command=old, reason="Interactive/internal command or malformed documentation heading; use the explicit corrected operation where present.", source=o['source']))
            continue
        o['command'] = RENAME.get(old, old)
        o['parameters'] = [p for p in o['parameters'] if p['name'] not in ('abc', 'attribute') or o['command'].startswith(('user attribute', 'user group attribute', 'object attribute'))]
        ops[o['command']] = o

    def add(cmd, source_cmd, params=()):
        src = ops[source_cmd]
        ops[cmd] = dict(command=cmd, parameters=[dict(name=n) for n in params], examples=[], source=src['source'], revision=src['revision'])

    def params(cmd, names):
        ops[cmd]['parameters'] = [dict(name=n) for n in names.split()]

    # Correct hidden headings and table rowspans; preserve the vendor's spelling.
    add('rule implied group get', 'rule implied group set')
    add('rule implied rule get', 'rule implied rule set')
    for name in ('group', 'rule'):
        ops['rule implied '+name+' get']['parameters'] = []
    for verb in ('confirm', 'decline'):
        for document in ('privacy', 'eula'):
            add('system upgrade '+verb+' '+document, 'system upgrade info')
    for document in ('privacy', 'eula'):
        add('system upgrade '+document+' get', 'system upgrade info', ['version', 'lang'])
    for cmd in ('geolocation info', 'system info', 'ipsec get'):
        ops[cmd]['parameters'] = []
    params('cluster maintainance set', 'value')
    params('manager new', 'hostlist'); params('manager set', 'hostlist')
    params('system config import', 'name filename')
    params('system register', 'input')
    params('object attribute set', 'name attribute value')
    params('ssh remote set', 'value')
    params('cert extension delete', 'id')
    params('rsa new', 'name bits'); params('rsa delete', 'id')
    params('rsa import', 'name format value'); params('rsa export', 'id format')
    params('cert new', 'name common_name bits valid_since valid_till issuer issuer_id country state location organization organization_unit email signature_algo flags')
    params('cert set', 'id name common_name email flags')
    for cmd in ('cert unrevoke','cert delete cert','cert delete key','cert delete crl','cert revoke','cert export x509','cert export privatekey','cert export crl'):
        params(cmd, 'id')
    params('cert export pkcs12','id password')
    params('cert import', 'input')
    params('cert extension add', 'id ext_name ext_value')
    params('cert acme_account reset', 'acme_account_id')
    params('cert acme_account set', 'flags')
    for c in ('cert acme_names status','cert acme_names verify'):
        params(c, 'acme_altname_list acme_apikey_list acme_alias_list')
    # Tables abbreviate updates as "same as new".
    for c in list(ops):
        if c.endswith(' set') and c[:-4]+' new' in ops:
            existing = {p['name'] for p in ops[c]['parameters']}
            ops[c]['parameters'] += [copy.deepcopy(p) for p in ops[c[:-4]+' new']['parameters'] if p['name'] not in existing]
    params('mail fetch new', 'host proto user pass flags dest_addr dest_domain envelope limit local remote oauth_account_user_id oauth_account oauth_user tls_version')
    params('interface mobile modem set', 'id bearerid pin enabled equipmentid')
    params('interface mobile modem new', 'bearerid pin enabled equipmentid')
    params('ipsec subnet set', 'subnet_id local_subnet remote_subnet')
    params('ipsec set', 'id name ike_version local_auth remote_auth local_secret remote_secret local_authobj remote_authobj local_subnet remote_subnet remote_subnet_within local remote local_id remote_id ike esp flags nexthop xfrm_if_name')
    params('user set','id name password groups')
    params('user attribute otpsecret','name')
    params('openvpn disconnect','name c_name')
    params('interface set','name type zones flags options qos')
    params('alertingcenter collectd set','plugin limit_severity_1 limit_severity_2 tolerance_time severity_1 severity_2')
    for cmd in ('dhcp param new','dhcp param set'):
        params(cmd,'pool default-lease-time max-lease-time deny next-server')
    for cmd in ('dhcp option new','dhcp option set'):
        params(cmd,'pool domain-name domain-name-servers routers netbios-name-servers smtp-server ntp-servers vendor-encapsulated-options tftp-server-name bootfile-name default-url vlan-id')
    for cmd in ('service new','service set'):
        params(cmd,('name' if cmd.endswith('new') else 'id')+' proto icmp-types src-ports dst-ports')
    # Positional bulk-list grammar is different from named scalar parameters.
    for cmd in ('extc cleanup overview','extc cleanup execute','extc valuelist get_with_state','extc valuelist set','extc valuelist default','extc valuelist get'):
        params(cmd,'entries')

    # Mail tag commands are documented in the application guide, not CLI/Mail.
    manifest = json.loads((ROOT / 'docs/securepoint/wiki-manifest.json').read_text())['pages']
    mail_source = next(p for p in manifest if p['title']=='UTM/APP/Mailfilter')
    for verb,names in [('add','mail tag'),('set','description tag'),('get',''),('purge','tag'),('remove','mail tag')]:
        cmd='mail filterng tag '+verb
        ops[cmd]=dict(command=cmd,parameters=[dict(name=n) for n in names.split()],examples=[],source=mail_source['url'],revision=mail_source['revision'])

    required = {
        'node new':'name address zone','node set':'id','node delete':'id','node group new':'name nodes','node group set':'id nodes','node group add':'id nodes','node group rem':'id nodes','node group delete':'id',
        'rule new':'group src dst service flags','rule set':'id','rule delete':'id','rule move':'id pos','rule group new':'name','rule group set':'id','rule group delete':'id','rule group move':'name pos','rule timeprofile new':'name','rule timeprofile set':'id','rule timeprofile delete':'id',
        'service new':'name proto','service set':'id','service group new':'name',
        'interface new':'name type','interface set':'name','interface delete':'name','interface rename':'id name','interface zone new':'name','interface zone set':'id','interface zone delete':'id','interface address new':'device address','interface address set':'id address','interface address delete':'id',
        'route new':'dst','route set':'id','route delete':'id','manager new':'hostlist','manager set':'hostlist',
        'dhcp pool new':'name start end','dhcp pool set':'id','dhcp pool delete':'name','dhcp lease new':'host ethernet ip','dhcp lease set':'host','dhcp lease delete':'host',
        'dns zone new':'zone_name','dns zone set':'zone_id','dns zone delete':'zone_id','dns record new':'zone_id type record_name value','dns record set':'record_id value','dns record delete':'record_id',
        'extc value set':'application variable value','extc value reset':'application variable','extc global set':'variable value','extc global new':'variable value','extc global reset':'variable','extc variable get':'application','extc new':'application variable value','extc delete':'application variable','extc template set':'template content','extc template get':'template','extc template getdiff':'template',
        'user new':'name password groups','user set':'id','user attribute set':'name attribute value','user attribute delete':'name attribute','user group new':'name','user group set':'id','user group attribute set':'name attribute value','user group attribute delete':'name attribute','user attribute otpsecret':'name',
        'system config import':'name filename','system config clone':'name new_name','system config new':'name','system config delete':'name','system config load':'name','system config set':'name','system date set':'date','system register':'input',
        'system tools ping':'host','system tools traceroute':'host','system tools host':'host','system tools wake':'host','system sysctl new':'name value','system sysctl set':'name value','system sysctl delete':'name',
        'cluster maintainance set':'value','object attribute set':'name attribute value','cert import':'input',
    }
    # Commands whose documentation explicitly says it does not know the syntax.
    unresolved = {'mail fetch map set':'The wiki leaves mapping parameters unspecified.',
                  'mail dkimsign domain set':'The wiki supplies neither parameters nor an example.',
                  'cert import':'The wiki marks this interactive syntax as obsolete since firmware 11.4; validate on 14.x first.'}
    # Activation metadata: only documented commands, no guessed daemon restarts.
    activation = {'node':['system update rule'],'service':['system update rule'],'rule':['system update rule'],
                  'interface':['system update interface'],'route':['system update route'],'qos':['system update qos'],
                  'ipsec':['ipsec update'],'openvpn':['openvpn update'],'wireguard':['wireguard update'],
                  'manager':['system update rule'],'wlan':['system update interface']}
    # App-specific reload commands from their references. Other EXTC settings
    # require an explicit companion application-restart plan chosen by the user.
    for c,o in sorted(ops.items()):
        o['id']='utm_'+c.replace(' ','_')
        o['group']=c.split()[0]
        o['kind']='read' if c.split()[-1] in READ_TAILS or c in EXPLICIT_READ or c in SENSITIVE_OUTPUT or c.startswith('cert export ') or c.startswith('view ') else 'change'
        if c in {'system config load_dryrun','system config synchronize_dryrun'}:o['kind']='change'
        o['sensitive_output']=c in SENSITIVE_OUTPUT or c=='user attribute otpsecret'
        o['lifecycle']=c in DISRUPTIVE or c.startswith(('system upgrade ', 'system remote upgrade ')) and o['kind']!='read'
        o['diagnostic']=c.startswith('debug kmod ') and o['kind']!='read'
        o['live_verified']=False
        o['minimum_firmware']='14.0.0'
        if c=='extc valuelist get_with_state':o['minimum_firmware']='14.0.1'
        o['activation']=activation.get(o['group'],[]) if o['kind']=='change' else []
        if c in o['activation'] or c.startswith(('system update ','appmgmt ')):o['activation']=[]
        if c.startswith('mail filterng ') and o['kind']=='change':o['activation']=['mail filterng update']
        if c.startswith('mail fetch ') and o['kind']=='change':o['activation']=['mail fetch update']
        if c.startswith('system sysctl ') and o['kind']=='change':o['activation']=['system update system']
        o['snapshot']=[]
        # Capture full relevant configured state, not changing counters/status.
        if o['kind']=='change':
            prefix=c.rsplit(' ',1)[0]
            candidate=prefix+' get'
            if candidate in ops and candidate!=c:
                o['snapshot']=[candidate]
            elif o['group'] in {'node','service','rule','interface','route','qos','user','cert','openvpn','ipsec','wireguard','server'}:
                o['snapshot']=[o['group']+' get']
            else:o['snapshot']=['system config get']
        if c.startswith('extc value ') or c.startswith('extc valuelist '):o['snapshot']=['extc value get'] if o['kind']=='change' else []
        if c.startswith('extc global '):o['snapshot']=['extc global get'] if o['kind']=='change' else []
        if c.startswith('system config ') and o['kind']=='change':o['snapshot']=['system config get']
        o['persistable']=o['kind']=='change' and not o['lifecycle'] and not c.startswith(('system config ','appmgmt ','system tools ','mail queue ','mail archive ','system remote ','debug ','system register','system cloudbackup ','geolocation ','wlan scan','alertingcenter test'))
        o['description']=('Read '+c+' from the selected UTM.' if o['kind']=='read' else 'Prepare '+c+' on the selected UTM; execute the returned change plan separately.')
        if c in unresolved:o['unavailable_reason']=unresolved[c];gaps.append(dict(command=c,reason=unresolved[c],source=o['source']))
        req=set(required.get(c,'').split())
        # Add simple key-value names supplied only by examples.
        for ex in o.get('examples',[]):
            if '\n' in ex:continue
            ex=re.sub(r'^\s*(?:cli>|spcli)\s*','',ex.strip())
            if not ex.startswith(c+' '):continue
            rest=ex[len(c):].strip()
            try:tokens=shlex.split(rest)
            except ValueError:continue
            i=0
            while i+1<len(tokens):
                key=tokens[i]
                if not re.fullmatch('[a-z][a-z0-9_-]*',key):break
                if key not in {p['name'] for p in o['parameters']}:o['parameters'].append(dict(name=key))
                i+=2
                if tokens[i-1]=='[':
                    while i<len(tokens) and tokens[i]!=']':i+=1
                    i+=1
        for p in o['parameters']:
            p['type']='value' if p['name']=='value' else 'array' if p['name'] in ARRAYS else 'scalar'
            p['required']=p['name'] in req
            p['description']='Securepoint CLI parameter '+p['name']+'.'
            if p['name']=='entries':p.update(type='entries',positional=True,required=True)
            if p['name']=='input':p.update(type='multiline',positional=True,required=True)
        if c=='cert extension delete':o['parameters'][0]['positional']=True
        if c.startswith('manager '):
            for p in o['parameters']:p['type']='array'
        if c.startswith('interface mobile modem ') and c.split()[-1] in ('enable','disable'):
            o['parameters'][0]['positional']=True
        if c in ('extc value set','extc new'):
            next(p for p in o['parameters'] if p['name']=='value')['type']='value'
        if c=='wireguard export':o['sensitive_output']=True
        o.pop('examples',None)

    # Built-in help on 14.1.5 exposes newer local interfaces absent from the
    # wiki's command tables. Preserve its grammar and provenance separately.
    live_path=(ROOT / 'docs/securepoint/appliance-command-schema.json')
    if live_path.exists():
        live=json.loads(live_path.read_text())
        overview=next(p for p in manifest if p['title']=='UTM/EXTRAS/CLI')
        excluded={'wrapper','help','quit','exit','logout','clear','cli json','cli echo on','cli echo off','system config setup','extc template edit','cert parse','transaction start','transaction commit','transaction rollback','usc_profile set','usc unlock','usc status'}
        for item in live['commands']:
            c=item['command']
            if c in excluded or c.startswith('system rsp '):continue
            syntax=item['usage']+' '+' '.join(item['additional_syntax'])
            body=syntax
            while body.startswith(c+' '):body=body[len(c):].strip()
            found=[]
            for m in re.finditer(r'\b([a-z_][a-z0-9_-]*)\s+(<[^>]*>|\{|\([^)]*\))',body):
                before=body[:m.start()]
                if before.count('{')!=before.count('}'):continue
                name,typ=m[1],m[2]
                if name in {p['name'] for p in found}:continue
                ptype='value' if typ=='{' else 'array' if '_array' in typ or typ=='<flags>' else 'scalar'
                if name in ARRAYS:ptype='array'
                found.append(dict(name=name,type=ptype,required=False,description='Securepoint CLI parameter '+name+'.'))
            if c not in ops:
                read=c.split()[-1] in READ_TAILS or c in {'system httpreports get','model get','nwkview get','debug show commit-id','ipsec cipher get'}
                o=dict(id='utm_'+c.replace(' ','_'),command=c,group=c.split()[0],kind='read' if read else 'change',
                       description=('Read ' if read else 'Prepare ')+c+' on the selected UTM.',
                       parameters=found,source=overview['url'],revision=overview['revision'],minimum_firmware=live['firmware'],
                       sensitive_output=c=='model get' or c.startswith('tcpdump '),lifecycle=c=='system postsync',diagnostic=c.startswith('tcpdump '),live_verified=False,
                       activation=[],snapshot=[] if read else ['system config get'],persistable=not read and not c.startswith(('tcpdump ','system postsync')))
                if not read and not found and c not in {'system postsync','system upgrade decline'}:
                    o['unavailable_reason']='Built-in help advertises the command without a parameter schema; an implementation-specific schema is still required.'
                ops[c]=o
            o=ops[c]
            o['observed_firmware']=live['firmware']
            o['syntax']=syntax.strip()
            # Merge only unambiguous top-level names, preserving reviewed wiki
            # semantics for positional/legacy/bulk commands.
            if c.startswith(('httpproxy ','wgmodel ','spdmsimd ','userbulk ')):
                o['parameters']=found
            elif c=='mail fetch map set':
                o['parameters']=[dict(name=n,type='scalar',required=n in {'id','remote'}) for n in ('id','remote','local')]
                o.pop('unavailable_reason',None)
            elif c=='cluster maintenance set':
                o['parameters']=[dict(name='value',type='scalar',required=True)]
                o.pop('unavailable_reason',None);o['lifecycle']=True;o['activation']=['system update interface'];o['snapshot']=['cluster maintenance get']
            elif c=='ipsec cipher get':
                o['parameters']=[dict(name='name',type='scalar',required=True)]
            elif c=='dns filter get_automatic_mode_addresses':
                o['kind']='read';o['persistable']=False;o['snapshot']=[];o.pop('unavailable_reason',None)
            elif c=='system config export_zip':
                o['parameters']=[dict(name='name',type='array',required=True)]
                o['kind']='read';o['sensitive_output']=True;o['persistable']=False;o['snapshot']=[];o.pop('unavailable_reason',None)
            elif c=='oauth update':
                o['parameters']=[];o['persistable']=False;o['snapshot']=['oauth get'];o.pop('unavailable_reason',None)
            elif c=='dhcp extra options':
                o['kind']='read';o['persistable']=False;o['snapshot']=[];o.pop('unavailable_reason',None)
            elif c in {'dhcp pool delete','dhcp lease delete','dhcp lease set'}:
                o['parameters']=[dict(name='id',type='scalar',required=True)]
                if c=='dhcp lease set':o['parameters'] += [dict(name=n,type='scalar',required=False) for n in ('host','ethernet','ip')]
                o['minimum_firmware']=live['firmware']
            if c=='mail stats users':o['kind']='read'
        # Retain detailed syntax as facts; do not claim a help listing proves a
        # mutation works, or enable old interactive certificate import.

    # Exact read invocations verified on firmware 14.1.5 are recorded without
    # appliance identifiers or configuration data.
    verified_path=(ROOT / 'docs/securepoint/live-read-verification.json')
    if verified_path.exists():
        verified=json.loads(verified_path.read_text())
        for c in verified.get('commands',[]):
            if c in ops and ops[c]['kind']=='read':ops[c]['live_verified']=True

    # Only a fixed root diagnostic is exposed; filter is shell-quoted as one arg.
    src=next(p for p in manifest if p['title']=='UTM/EXTRAS/Paket-Mitschnitte')
    ops['diagnostics tcpdump']=dict(id='utm_diagnostics_tcpdump',command='tcpdump',group='diagnostics',kind='read',
        description='Capture a bounded textual packet trace using root SSH. Output is sensitive.',
        parameters=[dict(name='interface',type='scalar',required=True),dict(name='count',type='integer',required=True),dict(name='filter',type='scalar',required=False)],
        shell=True,diagnostic=True,sensitive_output=True,live_verified=False,minimum_firmware='14.0.0',
        source=src['url'],revision=src['revision'],activation=[],snapshot=[],persistable=False)
    result=sorted(ops.values(),key=lambda o:o['id'])
    out=(ROOT / 'internal/securepoint/catalog/operations.json');out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    unavailable={o['command'] for o in result if o.get('unavailable_reason')}
    gaps=[g for g in gaps if g['command'] not in ops or g['command'] in unavailable]
    existing={g['command'] for g in gaps}
    gaps += [dict(command=o['command'],reason=o['unavailable_reason'],source=o['source']) for o in result if o['command'] in unavailable and o['command'] not in existing]
    (ROOT / 'docs/securepoint/coverage-gaps.json').write_text(json.dumps(gaps,indent=2)+'\n')
    print(f'Wrote {len(result)} typed operations, {sum(bool(o.get("unavailable_reason")) for o in result)} unavailable pending appliance schemas')


if __name__=='__main__':main()
