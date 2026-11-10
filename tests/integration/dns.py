#!/usr/bin/env python3
"""Passive DNS capture on a disposable bridge; never binds a real interface."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'runtime'), str(ROOT/'tests')]
from dns_ioc import DomainCatalog, observe_dns

SERVER = r'''
import json,select,socket,struct
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('198.51.100.53',53))
t=socket.socket();t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);t.bind(('198.51.100.53',53));t.listen(1)
done=0
while done<4:
 ready,_,_=select.select([u,t],[],[],10)
 assert ready,'private DNS client did not arrive'
 for sock in ready:
  if sock is u:
   raw,peer=u.recvfrom(4096);u.sendto(raw[:2]+b'\x81\x80'+raw[4:],peer)
  else:
   c,_=t.accept();c.settimeout(5)
   head=c.recv(2);size=struct.unpack('!H',head)[0];raw=b''
   while len(raw)<size:raw+=c.recv(size-len(raw))
   reply=raw[:2]+b'\x81\x80'+raw[4:];c.sendall(struct.pack('!H',len(reply))+reply);c.close()
  done+=1
print(json.dumps({'private_receiver_queries':done}))
'''
CLIENT = r'''
import json,socket,struct
def message(name,ident):
 labels=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'
 return struct.pack('!HHHHHH',ident,0x100,1,0,0,0)+labels+struct.pack('!HH',1,1)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('192.0.2.20',53001));u.settimeout(5)
for ident,name in enumerate(['bad.example','ip-api.com','bad.example.attacker.invalid'],1):
 raw=message(name,ident);u.sendto(raw,('198.51.100.53',53));reply,_=u.recvfrom(4096)
 assert reply==raw[:2]+b'\x81\x80'+raw[4:]
t=socket.socket();t.bind(('192.0.2.20',54001));t.settimeout(5);t.connect(('198.51.100.53',53))
raw=message('bad.example',99);t.sendall(struct.pack('!H',len(raw))+raw)
size=struct.unpack('!H',t.recv(2))[0];reply=b''
while len(reply)<size:reply+=t.recv(size-len(reply))
assert reply==raw[:2]+b'\x81\x80'+raw[4:];t.close()
print(json.dumps({'udp_replies':3,'tcp_replies':1,'all_query_and_reply_bytes_match':True}))
'''


def run(engine, expected, systemd_sandbox=False):
    if os.geteuid()!=0 or not all(shutil.which(x) for x in ('ip','python3')):
        return 77
    if hashlib.sha256(Path(engine).read_bytes()).hexdigest()!=expected:
        raise RuntimeError('engine pin differs')
    token=secrets.token_hex(4);names=['pdn'+token+x for x in ('b','c','s')]
    assert all(re.fullmatch(r'pdn[0-9a-f]{8}[bcs]',x) for x in names)
    created=[];children=[];unit=None
    def command(*args):return subprocess.run(args,capture_output=True,text=True,check=True,timeout=20).stdout
    def firewall():
        def stable(value):
            if isinstance(value,dict):return {k:stable(v) for k,v in value.items() if k not in {'packets','bytes','expires'}}
            if isinstance(value,list):return [stable(v) for v in value]
            return value
        return stable(json.loads(command('nft','-j','list','ruleset')))
    before=firewall() if shutil.which('nft') else None
    with tempfile.TemporaryDirectory(prefix='public0-dns-netns-',dir='/run') as td:
        work=Path(td);assert work.resolve().parent==Path('/run') and work.name.startswith('public0-dns-netns-')
        try:
            for ns in names:command('ip','netns','add',ns);created.append(ns)
            bridge,client,server=names
            for ns in names:command('ip','-n',ns,'link','set','lo','up')
            command('ip','-n',bridge,'link','add','dnsbr','type','bridge')
            command('ip','-n',bridge,'link','set','dnsbr','up')
            for side,ns,addr,route in [('c',client,'192.0.2.20/24','198.51.100.0/24'),('s',server,'198.51.100.53/24','192.0.2.0/24')]:
                command('ip','-n',bridge,'link','add','p'+side,'type','veth','peer','name','e'+side)
                command('ip','-n',bridge,'link','set','e'+side,'netns',ns)
                command('ip','-n',bridge,'link','set','p'+side,'master','dnsbr')
                command('ip','-n',bridge,'link','set','p'+side,'up')
                command('ip','-n',ns,'address','add',addr,'dev','e'+side)
                command('ip','-n',ns,'link','set','e'+side,'up')
                command('ip','-n',ns,'route','add',route,'dev','e'+side)
            template=(ROOT/'config/suricata-dns.yaml.j2').read_text()
            config=template.replace('{{ cs_public0_dns_log_directory | to_json }}',json.dumps(str(work))).replace('{{ cs_public0_dns_interface | to_json }}','"dnsbr"').replace('{{ cs_public0_dns_cluster_id | int }}','97')
            assert '{{' not in config
            (work/'dns.yaml').write_text(config)
            with (work/'engine.log').open('wb') as log:
                argv=[engine,'-c',str(work/'dns.yaml'),'--af-packet=dnsbr',
                      '--runmode=workers','--disable-detection','--set','sensor-name='+'1'*32]
                if systemd_sandbox:
                    unit='public0-dns-lab-'+token+'.service'
                    template=(ROOT/'config/cs-public0-dns.service.j2').read_text()
                    allowed={'Type','User','Group','WorkingDirectory','UMask','CPUQuota','MemoryMax',
                        'MemorySwapMax','TasksMax','LimitFSIZE','TimeoutStopSec','KillMode','Restart',
                        'NoNewPrivileges','CapabilityBoundingSet','AmbientCapabilities','PrivateTmp',
                        'PrivateDevices','ProtectSystem','ProtectHome','ProtectKernelTunables',
                        'ProtectKernelModules','ProtectControlGroups','RestrictSUIDSGID',
                        'RestrictRealtime','LockPersonality','RestrictAddressFamilies'}
                    properties=[line for line in template.splitlines() if line.partition('=')[0] in allowed]
                    properties+=['NetworkNamespacePath=/run/netns/'+bridge,'ReadWritePaths='+str(work)]
                    argv[-1]='sensor-name=${INVOCATION_ID}'
                    argv=['systemd-run','--quiet','--pipe','--wait','--collect','--unit='+unit,
                        '--expand-environment=yes',*[x for prop in properties for x in ('--property',prop)],*argv]
                else:argv=['ip','netns','exec',bridge,*argv]
                capture=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT)
                children.append(capture)
                for _ in range(60):
                    if capture.poll() is not None:raise RuntimeError((work/'engine.log').read_text()[-2000:])
                    if (work/'eve.json').exists() and (work/'eve.json').stat().st_size:break
                    time.sleep(.1)
                receiver=subprocess.Popen(['ip','netns','exec',server,'python3','-I','-B','-c',SERVER],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                children.append(receiver);time.sleep(.2)
                client_result=json.loads(command('ip','netns','exec',client,'python3','-I','-B','-c',CLIENT))
                receiver_out,receiver_err=receiver.communicate(timeout=15)
                assert receiver.returncode==0,receiver_err
                time.sleep(5.2)
                if unit:
                    invocation=command('systemctl','show',unit,'-p','InvocationID','--value').strip()
                    command('systemctl','stop',unit)
                else:invocation='1'*32;capture.terminate()
                capture.wait(timeout=15)
            data=(work/'eve.json').read_bytes();rows=[json.loads(x) for x in data.splitlines()]
            stats=[x for x in rows if x.get('event_type')=='stats'];dns=[x for x in rows if x.get('event_type')=='dns']
            assert re.fullmatch(r'[0-9a-f]{32}',invocation) and all(x.get('host')==invocation for x in rows)
            assert len(dns)==8,[(x['dns']['type'],x['dns'].get('queries')) for x in dns]
            now=int(time.time());catalog=DomainCatalog({'schema':'cs-public0-domain-catalog-v1','source':'threatfox','domains':['bad.example'],'sha256':'a'*64,'fetched_unix':now-100,'published_unix':now-100,'expires_unix':now+100})
            matched=[];offset=0
            for line in data.splitlines(keepends=True):
                ref={'device':0,'inode':0,'offset':offset,'length':len(line),'record_sha256':hashlib.sha256(line).hexdigest()};offset+=len(line)
                matched+=observe_dns(json.loads(line),{'sensor_id':'netns-fixture','owned_ipv4_networks':['192.0.2.0/24']},catalog,ref,now)
            assert len(matched)==2 and {x['proto'] for x in matched}=={'UDP','TCP'}
            final=stats[-1]['stats']['capture']
            assert final['kernel_drops']==0 and final['kernel_packets']>0,final
            if before is not None:assert firewall()==before,'root firewall policy changed'
            print(json.dumps({'status':'PASS_PASSIVE_DNS_NETNS','queries':4,'responses':4,'matched_queries':2,
                'capture':final,'client':client_result,'receiver':json.loads(receiver_out),
                'systemd_sandbox':systemd_sandbox,'producer_invocation_verified':True,
                'root_firewall_preserved':True,'physical_interfaces_used':False,'eve_sha256':hashlib.sha256(data).hexdigest()}))
            return 0
        finally:
            if unit:subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=20)
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:child.wait(timeout=8)
                    except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
            for ns in reversed(created):command('ip','netns','delete',ns)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',required=True);parser.add_argument('--engine-sha256',required=True)
    parser.add_argument('--systemd-sandbox',action='store_true')
    args=parser.parse_args();raise SystemExit(run(args.engine,args.engine_sha256,args.systemd_sandbox))
