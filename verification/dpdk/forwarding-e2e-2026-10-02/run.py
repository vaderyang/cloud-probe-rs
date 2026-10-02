import sys,pathlib,json,subprocess,shlex,time,fcntl,signal,re,concurrent.futures,traceback
P=pathlib.Path('/tmp/forwarding-e2e');R=str(P);CG='/sys/fs/cgroup/fwdbench';LD='/home/vader/dpdk-inst/lib/x86_64-linux-gnu'
sys.path.insert(0,'/tmp/legacy-probe');import live
live.WORK=P
sys.path.insert(0,R)
ssh=live.ssh
def ident():
 return {name:{key:subprocess.check_output(['git','-C',repo,*args],text=True) for key,args in [('head',['rev-parse','HEAD']),('refs',['show-ref']),('status',['status','--short'])]} for name,repo in [('rust','/home/vader/code/netis/cloud-probe-rs'),('C','/home/vader/code/netis/cloud-probe-github')]}
def put(host,path,body):ssh(host,'cat >'+shlex.quote(path)+" <<'FWDEOF'\n"+body+"\nFWDEOF")
def launch(host,cmd,log):
 ssh(host,'sudo -n setsid nohup bash -c '+shlex.quote('ulimit -c 0; exec '+cmd)+' >'+shlex.quote(R+'/'+log)+' 2>&1 </dev/null &')
def wait(host,log,marker,timeout=20):
 end=time.monotonic()+timeout;out=''
 while time.monotonic()<end:
  out=ssh(host,f'sudo -n cat {R}/{log}')
  if marker in out:return out
  if 'fatal error' in out.lower() or 'failed' in out.lower():raise RuntimeError(out)
  time.sleep(.1)
 raise RuntimeError(out)
def stop_worker():
 ssh('yinjiao',"sudo -n pkill -TERM -x cpworker || true")
 ssh('yinjiao',f"sudo -n sh -c 'if [ -f {CG}/cgroup.procs ]; then for p in $(cat {CG}/cgroup.procs); do kill -TERM $p; done; fi'\ntrue")
 end=time.monotonic()+10
 while time.monotonic()<end:
  if not ssh('yinjiao',f'cat {CG}/cgroup.procs 2>/dev/null || true'):break
  time.sleep(.2)
 else:raise RuntimeError('worker did not stop')
 ssh('yinjiao',f'sudo -n rm -f {R}/worker.sock')
def stop_primary():
 ssh('yinjiao',"sudo -n pkill -TERM -x dpdk_primary || true")
 time.sleep(.4)
 ssh('yinjiao',f'sudo -n rm -f {R}/primary-stats.json; sudo -n rm -rf /var/run/dpdk/rte')
def stop_rx():
 ssh('jinjiao',"sudo -n pkill -TERM -x receiver || true")
 time.sleep(.2)
def rpc():
 code='''import socket,struct,json
xid=0x46574431;body=struct.pack('!10I',xid,0,2,100003,4,0,0,0,0,0)
with socket.create_connection(('10.2.0.12',2049),timeout=3) as s:
 s.settimeout(3);s.sendall(struct.pack('!I',0x80000000|len(body))+body)
 def read(n):
  b=b''
  while len(b)<n:
   d=s.recv(n-len(b));assert d;b+=d
  return b
 b=b''
 while True:
  m=struct.unpack('!I',read(4))[0];b+=read(m&0x7fffffff)
  if m&0x80000000:break
 w=list(struct.unpack('!'+str(len(b)//4)+'I',b));ok=w==[xid,1,0,0,0,0];print(json.dumps({'ok':ok,'words':w}));assert ok
'''
 return json.loads(ssh('yinjiao','python3 -c '+shlex.quote(code)))
def audit():
 out={h:live.audit(h) for h in ['laojun','yinjiao']};out['rpc']=rpc()
 out['jinjiao']=ssh('jinjiao',"pgrep -ax receiver || true")
 return out
def setup():
 initial=audit();(P/'initial.json').write_text(json.dumps(initial,indent=2));(P/'identity-before.json').write_text(json.dumps(ident(),indent=2))
 for h in ['laojun','yinjiao']:
  assert initial[h]['vfs']==0 and initial[h]['processes']['rc']==1 and not initial[h]['dpdk']['stdout'],initial[h]
 for h in ['laojun','yinjiao','jinjiao']:
  ssh(h,f'mkdir -p {R}');put(h,R+'/sample.py',(P/'sample.py').read_text())
 put('jinjiao',R+'/receiver.c',(P/'receiver.c').read_text());ssh('jinjiao',f'cc -O3 -Wall {R}/receiver.c -o {R}/receiver -lzmq')
 for host,pf,vf,mac in [('yinjiao','ens8np0','ens8v0',live.DST),('laojun','ens72np0','ens72v0','12:e9:4b:91:bd:e0')]:
  ssh(host,f"sudo -n sh -c 'echo 1 > /sys/class/net/{pf}/device/sriov_numvfs'; sleep 2; sudo -n sysctl -q -w net.ipv6.conf.{vf}.disable_ipv6=1; sudo -n ip link set {vf} address {mac}; sudo -n ip link set {vf} up; sudo -n ip link set {pf} vf 0 max_tx_rate 0; sudo -n ethtool -A {pf} autoneg off rx off tx off")
 ssh('yinjiao','ping -c 1 -W 1 10.0.0.10 >/dev/null || true')
 ssh('yinjiao',f"sudo -n mkdir -p {CG}; sudo -n sh -c 'echo \"100000 100000\" > {CG}/cpu.max; echo 536870912 > {CG}/memory.max; echo 0 > {CG}/memory.swap.max; echo 536870912 > {CG}/hugetlb.2MB.max'")
def restore():
 errors=[]
 for fn in [stop_worker,stop_rx,stop_primary]:
  try:fn()
  except Exception as e:errors.append(str(e))
 for h,pf in [('laojun','ens72np0'),('yinjiao','ens8np0')]:
  try:
   ssh(h,f"sudo -n pkill -TERM -x capacity_tx || true\nsudo -n pkill -TERM -x legacy_capacity_tx || true\ntrue\nsudo -n sh -c 'echo 0 > /sys/class/net/{pf}/device/sriov_numvfs'\nsudo -n ethtool -A {pf} autoneg off rx on tx on\nsudo -n rm -rf /var/run/dpdk/rte\nsudo -n python3 /tmp/legacy-probe/clean_huge.py" if h=='yinjiao' else f"sudo -n pkill -TERM -x capacity_tx || true\nsudo -n pkill -TERM -x legacy_capacity_tx || true\ntrue\nsudo -n sh -c 'echo 0 > /sys/class/net/{pf}/device/sriov_numvfs'\nsudo -n ethtool -A {pf} autoneg off rx on tx on\nsudo -n rm -rf /var/run/dpdk/rte")
  except Exception as e:errors.append(str(e))
 ssh('yinjiao',f'sudo -n rm -f /dev/shm/fwdbench.pcap {R}/out.pcap; sudo -n rmdir {CG} 2>/dev/null || true')
 final=audit();initial=json.loads((P/'initial.json').read_text());checks={}
 for h in ['laojun','yinjiao']:
  a=final[h];checks[h]={'vfs0':a['vfs']==0,'pause_on':'RX:\t\ton' in a['pause']['stdout'] and 'TX:\t\ton' in a['pause']['stdout'],'no_processes':a['processes']['rc']==1,'dpdk_clean':not a['dpdk']['stdout'],'no_cores':not a['cores']['stdout'],'huge_unchanged':a['huge']==initial[h]['huge'],'link_up':'Link detected: yes' in a['link']['stdout']}
 checks['nfs']={'statfs':final['yinjiao']['nfs_statfs']['rc']==0,'rpc_null':final['rpc']['ok']};checks['receiver_stopped']=not final['jinjiao'];checks['repos_unchanged']=ident()==json.loads((P/'identity-before.json').read_text())
 (P/'restoration.json').write_text(json.dumps({'errors':errors,'checks':checks,'final':final},indent=2))
 assert not errors and all(all(v.values()) if isinstance(v,dict) else v for v in checks.values()),checks
 print('RESTORED AND VERIFIED',flush=True)
def snap(h):return json.loads(ssh(h,f'sudo -n python3 {R}/sample.py {h}'))
def both():
 with concurrent.futures.ThreadPoolExecutor(2) as p:return list(p.map(snap,['laojun','yinjiao']))
def counters(s):
 v=s['stats'];return {k:(q.get('packets',q.get('bytes',q)) if isinstance(q,dict) else q) for group in ['capture','output'] for k,q in v[group].items() if isinstance(q,(int,dict))}
def start(case):
 stop_worker();stop_rx()
 if case['backend']=='rdpdk':
  if not ssh('yinjiao',"pgrep -x dpdk_primary || true"):
   launch('yinjiao',f'env LD_LIBRARY_PATH={LD} PRIMARY_RXQ=4 PRIMARY_MBUF=32768 PRIMARY_STATS={R}/primary-stats.json /home/vader/cprs-bench/dpdk_primary -l 32-36 --log-level notice -a 0000:b8:00.1','primary.log');wait('yinjiao','primary.log','pdump_init=ok')
  cap={'type':'dpdk_pdump','dpdk_pdump':{'interface':'0000:b8:00.1','ring_size':65536,'bpf':''}}
 else:
  if ssh('yinjiao',"pgrep -x dpdk_primary || true"):stop_primary()
  c={'interface':'ens8v0','buffer_size_mb':8,'bpf':'','not_filter_output_hosts':True}
  if case['backend']!='cv2':c['timeout_ms']=1000
  if case['backend'] in ['rv3','rrecv']:c['ring']=case['backend']=='rv3'
  cap={'type':'libpcap','libpcap':c}
 output=case['output'];out={'type':output,'rate_limit_mbps':0}
 if output.startswith('file'):
  out={'type':'file','file':{'name':'/dev/shm/fwdbench.pcap' if output=='file_shm' else R+'/out.pcap'},'rate_limit_mbps':0}
  ssh('yinjiao',f'sudo -n rm -f {out["file"]["name"]}')
 elif output=='zmq':out['zmq']={'host':'10.0.0.10','port':19555,'hwm':1000,'service_tag':1,'heartbeat_ms':0}
 elif output=='vxlan':out['vxlan']={'host':'10.0.0.10','port':19556,'vni1':7,'bind_device':'ens5f0'}
 elif output=='gre':out['gre']={'host':'10.0.0.10','service_tag':7,'bind_device':'ens5f0'}
 if output in ['zmq','vxlan','gre']:
  ssh('jinjiao',f'sudo -n rm -f {R}/rx.json');launch('jinjiao',f'{R}/receiver {output} {19555 if output=="zmq" else 19556} {R}/rx.json','rx.log');wait('jinjiao','rx.log','RECEIVER_READY')
 cfg={'cpu_affinity':'48-49','execution_model':'rtc','control':{'type':'unix','unix':{'path':R+'/worker.sock'}},'tasks':[{'capturer':cap,'outputs':[out]}]}
 binary='/tmp/legacy-probe/cpworker' if case['backend'].startswith('c') else '/home/vader/cprs-bench/target/release/cpworker'
 put('yinjiao',R+'/worker.json',json.dumps(cfg));(P/(case['id']+'-config.json')).write_text(json.dumps(cfg,indent=2))
 body=f'ulimit -c 0; echo $$ > {CG}/cgroup.procs; exec env LD_LIBRARY_PATH={LD} {binary} -c {R}/worker.json'
 ssh('yinjiao','sudo -n setsid nohup bash -c '+shlex.quote(body)+f' >{R}/worker.log 2>&1 </dev/null &');wait('yinjiao','worker.log','create task-0 success')
 time.sleep(5.2 if case['backend'].startswith('c') else 1.2)
 if case['backend']!='rdpdk':(P/(case['id']+'-diag.json')).write_text(ssh('yinjiao','sudo -n python3 /tmp/legacy-probe/packet_diag.py'))
 return cfg
def measure(case):
 cfg=start(case);secs=case.get('seconds',4.0)
 if case['output']=='file_shm':secs=min(secs,3.8/case['target'])
 warm_log=None;rx_baseline=None
 if case.get('warm'):
  warm_log=ssh('laojun',f'sudo -n env LD_LIBRARY_PATH={LD} CAP_TX_MPPS=0.02 CAP_TX_SECONDS=1 CAP_TX_QUEUES=4 /tmp/capacity_tx --no-huge -m 512 -l 8-12 --log-level notice -a 0000:46:00.1 2>&1',timeout=20)
  assert 'CAP_TX_DONE' in warm_log,warm_log
  time.sleep(5.8 if case['backend'].startswith('c') else 2.5)
  if case['output'] in ['zmq','vxlan','gre']:
   # A stale receiver JSON or a partial batch is not a baseline. Wait until
   # warmup output and independent receive counts have closed and queues drained.
   warm_accepted=int(re.search(r'CAP_TX_DONE total=(\d+)',warm_log)[1])
   end=time.monotonic()+45
   while True:
    ws=snap('yinjiao');wc=counters(ws)
    rx_baseline=json.loads(ssh('jinjiao',f'sudo -n cat {R}/rx.json'))
    wd=sum(wc.get(k,0) for k in ['error_drop_packets','ratelimit_drop_packets','direction_drop_packets'])
    if wc['cap_packets']==warm_accepted and wc['fwd_packets']+wd==wc['cap_packets'] and rx_baseline['packets']==wc['fwd_packets'] and ws['stats']['output'].get('zmtp_queued_bytes',0)==0:break
    if time.monotonic()>end:raise RuntimeError('warmup failed to close: '+str((warm_accepted,wc,rx_baseline)))
    time.sleep(.3)
 before=both();startwall=time.time()
 for h in ['laojun','yinjiao']:launch(h,f'python3 {R}/sample.py {h} {secs+2.5}','sample.log')
 # Existing paced transmitter and templates, unchanged. Main waits one second before the short burst.
 tx=ssh('laojun',f'sudo -n env LD_LIBRARY_PATH={LD} CAP_TX_MPPS={case["target"]} CAP_TX_SECONDS={secs} CAP_TX_QUEUES=4 /tmp/capacity_tx --no-huge -m 512 -l 8-12 --log-level notice -a 0000:46:00.1 2>&1',timeout=secs+20)
 endwall=time.time();assert 'CAP_TX_DONE' in tx,tx
 # Quiet publication plus output-batch drain. C publishes every five seconds.
 time.sleep(5.8 if case['backend'].startswith('c') else 2.5)
 after=both()
 accepted=int(re.search(r'CAP_TX_DONE total=(\d+)',tx)[1])
 if case['output'] in ['zmq','vxlan','gre']:
  deadline=time.monotonic()+25
  while True:
   ca,cb=counters(before[1]),counters(after[1]);dc={k:cb[k]-ca.get(k,0) for k in cb if isinstance(cb[k],int)}
   od=sum(dc.get(k,0) for k in ['error_drop_packets','ratelimit_drop_packets','direction_drop_packets'])
   if dc['cap_packets']==dc['fwd_packets']+od and after[1]['stats']['output'].get('zmtp_queued_bytes',0)==0:break
   if time.monotonic()>deadline:raise RuntimeError('post-burst output counters did not drain: '+str(dc))
   time.sleep(.4);after=both()
 series=[json.loads(ssh(h,f'sudo -n cat {R}/samples.json')) for h in ['laojun','yinjiao']]
 c0,c1=counters(before[1]),counters(after[1]);delta={k:c1[k]-c0.get(k,0) for k in c1 if isinstance(c1[k],int)}
 cap=delta['cap_packets'];fwd=delta['fwd_packets']
 workerlog=ssh('yinjiao',f'sudo -n cat {R}/worker.log')
 stop_worker();time.sleep(.3)
 receiver=None
 if case['output'] in ['zmq','vxlan','gre']:
  stop_rx();receiver=json.loads(ssh('jinjiao',f'sudo -n cat {R}/rx.json'))
  if rx_baseline:
   receiver['whole_run']=dict(receiver);receiver['warmup']=rx_baseline
   for k in ['packets','inner_bytes','messages','payload_bytes','bad','socket_drops']:receiver[k]-=rx_baseline[k]
  delivered=receiver['packets'];outbytes=receiver['payload_bytes']
 elif case['output'].startswith('file'):
  filename=cfg['tasks'][0]['outputs'][0]['file']['name']
  # Independently parse every record, including inner template validation; no inferred count from filesize.
  code='''import json,struct,mmap,os,time
f=open(PATH,'rb');size=os.fstat(f.fileno()).st_size;m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);magic,maj,min,tz,sig,snap,link=struct.unpack_from('<IHHIIII',m);assert magic==0xa1b2c3d4 and snap==2048 and link==1
pos=24;n=0;bad=0
while pos+16<=size:
 sec,usec,cap,wire=struct.unpack_from('<IIII',m,pos);pos+=16
 if pos+cap>size:break
 if cap!=64 or wire!=64 or m[pos:pos+6]!=bytes.fromhex('1aca0a26a88c') or m[pos+12:pos+14]!=bytes.fromhex('0800'):bad+=1
 pos+=cap;n+=1
print(json.dumps({'packets':n,'inner_bytes':n*64,'file_bytes':size,'bad':bad,'trailing_bytes':size-pos,'snaplen':snap}))
t=time.monotonic();os.fsync(f.fileno());print(json.dumps({'fsync_seconds':time.monotonic()-t}))
'''.replace('PATH',repr(filename))
  lines=ssh('yinjiao','sudo -n python3 -c '+shlex.quote(code),timeout=60).splitlines();receiver=json.loads(lines[0]);receiver.update(json.loads(lines[1]));delivered=receiver['packets'];outbytes=receiver['file_bytes']
  readercfg={'execution_model':'rtc','control':{'type':'unix','unix':{'path':R+'/worker.sock'}},'tasks':[{'capturer':{'type':'pcap_file','pcap_file':{'file_name':filename}},'outputs':[{'type':'null'}]}]}
  put('yinjiao',R+'/reader.json',json.dumps(readercfg))
  launch('yinjiao',f'env LD_LIBRARY_PATH={LD} /home/vader/cprs-bench/target/release/cpworker -c {R}/reader.json','reader.log');wait('yinjiao','reader.log','end of file');time.sleep(1.1)
  ctl=ssh('yinjiao',f'sudo -n env LD_LIBRARY_PATH={LD} /home/vader/cprs-bench/target/release/cpctl -u {R}/worker.sock -f jsonl stats -n 1')
  (P/(case['id']+'-reader-cpctl.jsonl')).write_text(ctl);readerstats=json.loads(ctl.splitlines()[-1]);receiver['repo_reader_packets']=readerstats['counters']['cap_packets']['packets'];assert receiver['repo_reader_packets']==delivered,(receiver,ctl)
  ssh('yinjiao',"sudo -n pkill -TERM -x cpworker || true");time.sleep(.25);ssh('yinjiao',f'sudo -n rm -f {R}/worker.sock')
  ssh('yinjiao',f'sudo -n rm -f {filename}')
 else:delivered=None;outbytes=0
 ys=series[1];active=[s for s in ys if startwall+1.3<s['wall']<endwall-.15]
 if len(active)<2:active=ys
 y0,y1=active[0],active[-1];dt=y1['time']-y0['time'];cpu=(y1['cpu']['usage_usec']-y0['cpu']['usage_usec'])/dt/1e6
 vfdrop=after[1].get('vf',{}).get('rx_out_of_buffer',0)-before[1].get('vf',{}).get('rx_out_of_buffer',0)
 outputdrop=sum(delta.get(k,0) for k in ['error_drop_packets','ratelimit_drop_packets','direction_drop_packets'])
 accounted=cap+delta.get('drop_packets',0)+vfdrop
 primary=None
 if 'primary' in after[1]:
  primary={k:after[1]['primary'].get(k,0)-before[1]['primary'].get(k,0) for k in ['rx','accepted','ringfull','nombuf','filtered','imissed','rx_nombuf']}
  accounted=cap+primary['ringfull']+primary['nombuf']+primary['filtered']+primary['imissed']+primary['rx_nombuf']
 r={**case,'seconds':secs,'accepted':accepted,'captured':cap,'forwarded':fwd,'delivered':delivered,'offered_mpps':accepted/secs/1e6,'captured_mpps':cap/secs/1e6,'delivered_mpps':delivered/secs/1e6 if delivered is not None else None,'worker_cpu_pct':cpu*100,'worker_cpu_us_per_capture':cpu/(cap/secs)*1e6 if cap else None,'cpu_window_seconds':dt,'output_bytes':outbytes,'delta':delta,'capture_accounting_residual':accepted-accounted,'post_forward_missing':None if delivered is None else fwd-delivered,'output_drop_packets':outputdrop,'vf_oob':vfdrop,'receiver':receiver,'primary_delta':primary,'memory_max':max(s['memory'] for s in ys),'throttled_periods':y1['cpu']['nr_throttled']-y0['cpu']['nr_throttled'],'oom_kill':after[1]['events']['oom_kill']-before[1]['events']['oom_kill'],'before':before,'after':after,'series':series,'worker_log':workerlog,'tx_log':tx}
 r['warm_log']=warm_log;r['warmup_receiver']=rx_baseline
 (P/(case['id']+'-result.json')).write_text(json.dumps(r));
 with (P/'results.jsonl').open('a') as f:f.write(json.dumps(r)+'\n')
 print(json.dumps({k:r[k] for k in ['id','seconds','offered_mpps','captured_mpps','delivered_mpps','worker_cpu_pct','capture_accounting_residual','post_forward_missing','output_drop_packets','memory_max','oom_kill']}),flush=True)
 return r
def main():
 cases=json.loads(pathlib.Path(sys.argv[1]).read_text());lock=open('/tmp/legacy-probe/physical.lock','w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 signal.signal(signal.SIGTERM,lambda *a:sys.exit(143));signal.signal(signal.SIGINT,lambda *a:sys.exit(130))
 try:
  setup()
  import report
  report.init()
  for index,case in enumerate(cases):
   try:
    print('START '+case['id'],flush=True)
    measure(case)
    if index+1==len(cases) or (cases[index+1]['backend'],cases[index+1]['output'])!=(case['backend'],case['output']):
     report.table(case['backend'],case['output'],'Completed continuation sweep — '+case['backend']+' / '+case['output'],'cont-')
   except Exception as e:
    (P/(case['id']+'-error.txt')).write_text(traceback.format_exc());print('ERROR '+case['id']+' '+str(e),flush=True)
    if 'warmup failed to close:' in str(e):
     report.append('Unmeasured preflight failure: `'+case['id']+'`; warmup did not close receiver accounting. Error/raw counters: `'+case['id']+'-error.txt`. No delivered capacity cell inferred.')
     stop_worker();stop_rx();continue
    raise
 finally:restore()
if __name__=='__main__':main()
