import sys,json,time,pathlib,socket,subprocess,re,os
P=pathlib.Path('/tmp/forwarding-e2e');CG=pathlib.Path('/sys/fs/cgroup/fwdbench')
def run(args):return subprocess.check_output(args,text=True)
def nic(iface):
 return {m[1]:int(m[2]) for l in run(['ethtool','-S',iface]).splitlines() if (m:=re.match(r'\s*([^:]+):\s*(\d+)\s*$',l)) and re.search('packets_phy|bytes_phy|rx_packets$|drop|discard|error|out_of_buffer',m[1])}
def fields(p):return {a:int(b) for a,b in (l.split() for l in p.read_text().splitlines())}
def stats():
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
  s.settimeout(4);s.connect(str(P/'worker.sock'));f=s.makefile('rwb');f.write(b'{"version":"v1"}\n');f.flush();assert json.loads(f.readline())['status']=='OK';f.write(b'{"command":"collect_stats_summary"}\n');f.flush();return json.loads(f.readline())
def snap(host,capture=True):
 a={'wall':time.time(),'time':time.monotonic()}
 a['nic']=nic('ens8np0' if host=='yinjiao' else ('ens72np0' if host=='laojun' else 'ens5f0'))
 if host=='yinjiao':
  if pathlib.Path('/sys/class/net/ens8v0').exists():a['vf']=nic('ens8v0')
  a['outnic']=nic('ens5f0');a['cpu']=fields(CG/'cpu.stat');a['memory']=int((CG/'memory.current').read_text());a['peak']=int((CG/'memory.peak').read_text()) if (CG/'memory.peak').exists() else a['memory'];a['events']=fields(CG/'memory.events');a['limits']={k:(CG/k).read_text().strip() for k in ['cpu.max','memory.max','memory.swap.max','cgroup.procs','hugetlb.2MB.current']}
  if capture and (P/'worker.sock').exists():
   t=time.monotonic();a['stats']=stats();a['rpc_seconds']=time.monotonic()-t
  if (P/'primary-stats.json').exists():a['primary']=json.loads((P/'primary-stats.json').read_text())
  a['memory_stat']=fields(CG/'memory.stat');a['io_stat']=(CG/'io.stat').read_text();a['proc']={}
  for name in ['cpworker','dpdk_primary']:
   for pid in subprocess.run(['pgrep','-x',name],text=True,capture_output=True).stdout.split():
    try:
     f=pathlib.Path('/proc/'+pid+'/stat').read_text();q=f[f.rfind(')')+2:].split();a['proc'][name]={'pid':int(pid),'utime':int(q[11]),'stime':int(q[12]),'hz':os.sysconf('SC_CLK_TCK'),'wchan':pathlib.Path('/proc/'+pid+'/wchan').read_text().strip()}
    except FileNotFoundError:pass
 a['udp']=pathlib.Path('/proc/net/snmp').read_text();a['softnet']=pathlib.Path('/proc/net/softnet_stat').read_text()
 return a
if __name__=='__main__':
 if len(sys.argv)>2:
  secs=float(sys.argv[2]);t=time.monotonic();samples=[]
  while time.monotonic()-t<secs:
   a=snap(sys.argv[1],False);samples.append(a);time.sleep(.2)
  (P/'samples.json').write_text(json.dumps(samples))
 else:print(json.dumps(snap(sys.argv[1])))










