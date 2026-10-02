import json,pathlib,collections,csv,sys
P=pathlib.Path('/tmp/forwarding-e2e')
BACKENDS={'cv3':'C real libpcap V3 (ordinary libpcap)','cv2':'C real libpcap V2 (timeout omitted)','rv3':'Rust libpcap ring:true V3','rrecv':'Rust libpcap ring:false recvmsg','rdpdk':'Rust dpdk_pdump (65536)'}
OUTPUTS=['null','file_shm','file_disk','zmq','vxlan','gre']
def rows():
 rs=[json.loads(l) for l in (P/'results.jsonl').read_text().splitlines() if not json.loads(l)['id'].startswith('smoke')]
 for r in rs:
  # Use physical input to select fully loaded intervals, not orchestration wall time:
  # EAL startup varies by hundreds of ms and otherwise dilutes CPU with idle time.
  intervals=[]
  for a,b in zip(r['series'][1],r['series'][1][1:]):
   dt=b['time']-a['time'];rate=(b['nic']['rx_packets_phy']-a['nic']['rx_packets_phy'])/dt/1e6
   if .90*r['offered_mpps']<rate<1.10*r['offered_mpps']:intervals.append((a,b,dt))
  r['uncorrected_worker_cpu_pct']=r['worker_cpu_pct']
  if intervals:
   dt=sum(q[2] for q in intervals);usec=sum(b['cpu']['usage_usec']-a['cpu']['usage_usec'] for a,b,_ in intervals);r['worker_cpu_pct']=usec/dt/1e4;r['cpu_window_seconds']=dt;r['cpu_method']='NIC-confirmed loaded intervals';r['cpu_windows']=[(a['time'],b['time']) for a,b,_ in intervals]
  else:r['cpu_method']='short burst: orchestration window includes idle';r['cpu_windows']=[]
 return rs
def lossfree(r):
 n=r['captured'] if r['delivered'] is None else r['delivered']
 return n==r['accepted'] and r['capture_accounting_residual']==0 and r['output_drop_packets']==0 and not r['oom_kill'] and (r['receiver'] is None or not r['receiver']['bad'])
def validate(rs):
 checks=[]
 for r in rs:
  ss=[r['before'][1],*r['series'][1],r['after'][1]];d=r['delta'];recv=r['receiver'];primary=r['primary_delta']
  capdrops=r['vf_oob']+d['drop_packets'] if not primary else sum(primary[k] for k in ['ringfull','nombuf','filtered','imissed','rx_nombuf'])
  downstream=0 if r['delivered'] is None else r['forwarded']-r['delivered']
  predicates={'no_oom':r['oom_kill']==0,'limits':all(s['limits']['cpu.max']=='100000 100000' and s['limits']['memory.max']=='536870912' and s['limits']['memory.swap.max']=='0' for s in ss),'worker_only':all(len(s['limits']['cgroup.procs'].split())==1 for s in ss),'capture_accounting':r['accepted']==r['captured']+capdrops,'cap_bytes_64':d['cap_bytes']==64*r['captured'],'output_accounting':r['captured']==r['forwarded']+r['output_drop_packets'],'e2e_accounting':r['delivered'] is None or r['accepted']==r['delivered']+capdrops+r['output_drop_packets']+downstream,'no_receiver_parse_errors':recv is None or recv['bad']==0,'no_unaccounted_downstream_loss':downstream==0 if not recv or 'socket_drops' not in recv else downstream==recv['socket_drops']}
  if r['output'].startswith('file'):predicates.update({'reader_equals_parser':recv['repo_reader_packets']==recv['packets'],'file_length':recv['file_bytes']==24+80*recv['packets'] and recv['trailing_bytes']==0})
  checks.append({'id':r['id'],'checks':predicates,'loss_free':lossfree(r),'downstream_gap':downstream,'capture_residual':r['capture_accounting_residual']})
 (P/'validation.json').write_text(json.dumps(checks,indent=2))
 return checks
def summarize(rs):
 for b in BACKENDS:
  for o in OUTPUTS:
   qs=[r for r in rs if r['backend']==b and r['output']==o]
   if not qs:continue
   good=[r for r in qs if lossfree(r)];bad=[r for r in qs if not lossfree(r)];lf=max(good,key=lambda r:r['offered_mpps']) if good else None
   print(b,o,'LF',f'{lf["offered_mpps"]:.6f}' if lf else 'none','peak',max(r['delivered_mpps'] or r['captured_mpps'] for r in qs),'fail',[(r['target'],r['accepted']-(r['delivered'] if r['delivered'] is not None else r['captured'])) for r in bad],'cpu',[round(r['worker_cpu_pct'],1) for r in qs])
def compact(rs):
 out=[]
 for r in rs:
  d=r['delta'];p=r['primary_delta'];out.append({k:r[k] for k in ['id','backend','output','target','seconds','accepted','captured','forwarded','delivered','offered_mpps','captured_mpps','delivered_mpps','worker_cpu_pct','output_drop_packets','vf_oob','capture_accounting_residual','post_forward_missing','memory_max','oom_kill']}|{'capture_socket_drops':d['drop_packets'],'fwd_bytes':d['fwd_bytes'],'error_drop_packets':d['error_drop_packets'],'ratelimit_drop_packets':d['ratelimit_drop_packets'],'direction_drop_packets':d['direction_drop_packets'],'primary_ringfull':p['ringfull'] if p else None,'receiver_socket_drops':r['receiver'].get('socket_drops',0) if r['receiver'] else None,'loss_free':lossfree(r)})
 if out:
  with (P/'measurements.csv').open('w') as f:w=csv.DictWriter(f,fieldnames=list(out[0]));w.writeheader();w.writerows(out)
def report():
 rs=rows();validate(rs);compact(rs);summarize(rs)
if __name__=='__main__':report()
