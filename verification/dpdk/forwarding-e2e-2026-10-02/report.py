"""Append completed tables durably; reuse analyze.py's CPU interval method."""
import json, pathlib, os, sys
import analyze
P = pathlib.Path('/tmp/forwarding-e2e')
REPORT = pathlib.Path('/tmp/forwarding_e2e_report.md')

def append(body):
    with REPORT.open('a') as f:
        f.write(body + '\n\n'); f.flush(); os.fsync(f.fileno())

def rows():
    rs = []
    for p in sorted(P.glob('*-result.json')):
        r = json.loads(p.read_text())
        if r['id'].startswith('smoke'): continue
        intervals = []
        for a,b in zip(r['series'][1],r['series'][1][1:]):
            dt=b['time']-a['time']
            rate=(b['nic']['rx_packets_phy']-a['nic']['rx_packets_phy'])/dt/1e6
            if .90*r['offered_mpps'] < rate < 1.10*r['offered_mpps']:
                intervals.append((a,b,dt))
        r['cpu_valid'] = bool(intervals)
        if intervals:
            dt=sum(q[2] for q in intervals)
            r['worker_cpu_pct']=sum(b['cpu']['usage_usec']-a['cpu']['usage_usec'] for a,b,_ in intervals)/dt/1e4
            r['cpu_window_seconds']=dt
        rs.append(r)
    return rs

def cell(r):
    if r is None: return 'not measured'
    delivered='—' if r['delivered'] is None else f"{r['delivered_mpps']:.6f}"
    cpu=f"{r['worker_cpu_pct']:.1f}" + ('' if r['cpu_valid'] else '*')
    return f"{r['captured_mpps']:.6f} / {r['forwarded']/r['seconds']/1e6:.6f} / {delivered}; {cpu}%; {r['output_drop_packets']:,}"

def table(backend, output, title, prefix=None):
    rs=rows(); selected=[r for r in rs if r['backend']==backend and r['output']==output and (prefix is None or r['id'].startswith(prefix))]
    selected.sort(key=lambda r:(r['target'],r['id']))
    out=[f'### {title}', '', 'Each backend cell: **captured / forwarded / delivered Mpps; worker CPU; output drops (packets)**. Null delivered is inapplicable.', '', '| Case / offered Mpps | Rust AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C immediate/V2 |', '|---|---|---|---|']
    for r in selected:
        peers={b:next((q for q in sorted(rs,key=lambda z:(z['id'].startswith('cont-'),z['id']),reverse=True) if q['backend']==b and q['output']==output and q['target']==r['target']),None) for b in ['rv3','cv3','cv2']}
        peers[backend]=r
        out.append(f"| `{r['id']}` / {r['offered_mpps']:.6f} | " + ' | '.join(cell(peers[b]) for b in ['rv3','cv3','cv2'])+' |')
    out += ['', '| Case | Capture socket drops | VF RX out of buffer | Output error / rate / direction drops | Output stats: fwd bytes | Receiver stats (packets / messages / socket drops / malformed) | Peak sampled cgroup MiB | CPU window s |', '|---|---:|---:|---|---:|---|---:|---:|']
    for r in selected:
        d=r['delta']; recv=r['receiver']; own='n/a' if recv is None else f"{recv['packets']:,} / {recv.get('messages','file records')} / {recv.get('socket_drops',0)} / {recv['bad']}"
        if recv and 'file_bytes' in recv: own+=f"; file={recv['file_bytes']:,} B, fsync={recv['fsync_seconds']:.3f}s"
        if 'zmtp_queued_bytes' in r['after'][1]['stats']['output']:
            own+=f"; ZMTP final queue={r['after'][1]['stats']['output']['zmtp_queued_bytes']} B"
        out.append(f"| `{r['id']}` | {d['drop_packets']:,} | {r['vf_oob']:,} | {d['error_drop_packets']:,} / {d['ratelimit_drop_packets']} / {d['direction_drop_packets']} | {d['fwd_bytes']:,} | {own} | {r['memory_max']/2**20:.1f} | {r['cpu_window_seconds']:.2f} |")
    good=[r for r in selected if analyze.lossfree(r)]
    bad=[r for r in selected if not analyze.lossfree(r)]
    out+=['',f"Measured loss-free point: {max(r['offered_mpps'] for r in good):.6f} Mpps." if good else 'No strictly loss-free point in these rows.',f"First measured non-loss-free offered load: {min(r['offered_mpps'] for r in bad):.6f} Mpps (inspect startup/steady-state and drop attribution below)." if bad else 'No knee bracketed by these rows.']
    append('\n'.join(out))

def init():
    if REPORT.exists(): return
    append('''# cloud-probe forwarding and end-to-end measurement

Started continuation 2026-10-02 UTC. Results are appended after each completed output sweep. Raw cases/configs/packet-socket diagnostics are in `/tmp/forwarding-e2e/`; saved runs are reused, not regenerated silently.

Product worker limits: `cpu.max=100000 100000`, `memory.max=536870912`, `memory.swap.max=0`. Only cpworker is in this cgroup; generator and receiver are outside. Affinity 48–49 allows migration, but aggregate CPU quota is one core. Run-to-completion execution model, one capture task/output, 64-byte Ethernet frames (68 NIC physical bytes including FCS), no configured BPF/rate limit. Capture ring buffer configured 8 MiB (explicit bench size; shipped config default is 256 MiB). Rust shipped backend is `libpcap` with `ring:true`, implemented directly with AF_PACKET TPACKET_V3. Saved/new comparable ring rows set timeout_ms=1000; Rust ring retirement is 1 ms regardless (verify source/diag), whereas C libpcap uses V3 for this timeout. C timeout omitted means immediate/V2. Socket diagnostics prove backend selection.

Input: laojun ens72np0/VF 0000:46:00.1 → yinjiao ens8np0/ens8v0 (0000:b8:00.1, MAC 1a:ca:0a:26:a8:8c), paced `/tmp/capacity_tx`, four TX queues. Physical tests serialized with `/tmp/legacy-probe/physical.lock`; 100 GbE carries NFS. Output peer: yinjiao ens5f0 (10.0.0.11) → jinjiao ens5f0 (10.0.0.10), 25 GbE. Receiver counts validated inner frames using C libzmq PULL or UDP recvmmsg/SO_RXQ_OVFL. `pcap_file` is the descriptive output name; actual config is `type:file`, `file.name` (type:pcap_file is a capturer).

File destinations: `/dev/shm/fwdbench.pcap` is tmpfs; `/tmp/forwarding-e2e/out.pcap` is local ext4 on LVM backed by Samsung NVMe devices, not NFS. Buffered-write delivery is parsed complete pcap records after worker shutdown, independently cross-checked with repo pcap_file reader; post-run fsync time is separate. This is short-burst buffered file throughput, not sustained durable disk throughput. tmpfs tests are shortened to stay below 512 MiB because file pages are charged to the worker cgroup.

Counter windows: packet totals use quiet snapshots before generation and after drain/publication, divided by generator burst duration (normally 4 s). C publishes every 5 s: waits 5.2 s before, 5.8 s after; Rust waits 1.2/2.5 s. CPU uses cgroup usage deltas only across ~0.2 s sample intervals whose physical PF RX rate is within ±10% of burst offered rate. CPU window therefore differs from packet window. Rates near the boundary are short-burst observations, not a sustained certified limit. No CPU extrapolation from null proves real-output capacity. A disk, output device, peer, or capture path can bind before the worker quota.

Cells labelled not measured are genuinely absent; no counter-derived rate is substituted for a receiver count. Output fwd counters mean accepted by the output API/queue, not necessarily delivered. Closed e2e accounting uses observed drop counters, never the downstream gap itself as an invented drop counter. Final restore verification is appended at the end.''')
    for o in ['null','file_disk','file_shm','zmq','vxlan']:
        table('rv3',o,'1. Recovered Rust ring results — '+o)

if __name__=='__main__':
    init()
    if len(sys.argv)>1: table(*sys.argv[1:])
