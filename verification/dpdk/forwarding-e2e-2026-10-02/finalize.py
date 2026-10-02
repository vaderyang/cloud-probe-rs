"""Summarize actual measurements; do not invent drop counters from a gap."""
import json, pathlib, sys, collections
import report, analyze
P=report.P

def selected():
    rs=report.rows()
    # Exclude historical network rows with the default output-host BPF.
    rs=[r for r in rs if r['output'] not in ['zmq','vxlan','gre'] or r['id'].startswith('cont-')]
    best={}
    for r in sorted(rs,key=lambda r:(r['id'].startswith('cont-'),r['id'])):
        best[(r['backend'],r['output'],r['target'])]=r
    return list(best.values())

def audit(rs):
    checks=[]
    for r in rs:
        d=r['delta'];receiver=r['receiver']
        capdrop=d['drop_packets']+r['vf_oob']
        if r['primary_delta']:
            capdrop=sum(r['primary_delta'][k] for k in ['ringfull','nombuf','filtered','imissed','rx_nombuf'])
        peer=receiver.get('socket_drops',0) if receiver else 0
        # A downstream difference is a residual, never a fabricated drop counter.
        residual=None if r['delivered'] is None else r['accepted']-r['delivered']-capdrop-r['output_drop_packets']-peer
        s=[r['before'][1],*r['series'][1],r['after'][1]]
        predicates={
            'worker_limits':all(q['limits']['cpu.max']=='100000 100000' and q['limits']['memory.max']=='536870912' and q['limits']['memory.swap.max']=='0' for q in s),
            'worker_only':all(len(q['limits']['cgroup.procs'].split())==1 for q in s),
            'capture_closed':r['accepted']==r['captured']+capdrop,
            'output_closed':r['captured']==r['forwarded']+r['output_drop_packets'],
            'e2e_closed':residual in [None,0],
            'no_malformed':not receiver or receiver['bad']==0,
            'no_oom':r['oom_kill']==0,
            'cap_bytes_64':d['cap_bytes']==64*r['captured'],
        }
        if receiver and 'file_bytes' in receiver:
            predicates['pcap_parser_reader']=receiver['packets']==receiver['repo_reader_packets'] and receiver['file_bytes']==24+80*receiver['packets'] and receiver['trailing_bytes']==0
        checks.append({'id':r['id'],'checks':predicates,'capture_drops':capdrop,'peer_drops':peer,'independent_e2e_residual':residual})
    (P/'continuation-validation.json').write_text(json.dumps(checks,indent=2))
    return checks

def summary(rs):
    lines=['## Completed scope: delivered limits, knees and binding constraints','','Highest loss-free means every generator-accepted packet was counted at the receiver (or capture for null), with zero drops and accounting residual, in the measured short burst. It is a measured point, not a sustained maximum guarantee. Historical filtered network runs are excluded. First strict loss includes isolated host-policy errors; the separate capture-capacity knee bracket ignores those output errors and brackets the onset of socket/VF capture loss.','','| Backend | Output | Highest measured loss-free Mpps | First strict lossy load Mpps | Capture-capacity knee bracket Mpps | Peak delivered Mpps (null: captured) | Constraint evidenced at knee |','|---|---|---:|---:|---|---:|---|']
    for b in ['rv3','cv3','cv2','rrecv','rdpdk']:
        for o in ['null','file_disk','file_shm','zmq','vxlan']:
            qs=sorted([r for r in rs if r['backend']==b and r['output']==o],key=lambda r:r['offered_mpps'])
            if not qs:continue
            good=[r for r in qs if analyze.lossfree(r)];bad=[r for r in qs if not analyze.lossfree(r)]
            lf=f"{max(r['offered_mpps'] for r in good):.6f}" if good else 'none'
            fail=f"{min(r['offered_mpps'] for r in bad):.6f}" if bad else 'not bracketed'
            cg=[r for r in qs if r['captured']==r['accepted']]
            cb=[r for r in qs if r['captured']<r['accepted']]
            lo=max((r['offered_mpps'] for r in cg),default=0)
            hi=min((r['offered_mpps'] for r in cb if r['offered_mpps']>lo),default=None)
            knee=f'({lo:.3f}, {hi:.3f}]' if hi is not None else f'> {lo:.3f}; not bracketed'
            peak=max(r['delivered_mpps'] if r['delivered'] is not None else r['captured_mpps'] for r in qs)
            if any(r['worker_cpu_pct']>90 and r['delta']['drop_packets']+r['vf_oob']>0 for r in bad):constraint='one-core CPU saturation at higher loads; capture/RX backpressure'
            elif any(r['vf_oob']>0 for r in bad):constraint='capture / host RX path (VF OOB); worker below quota'
            elif any(r['output_drop_packets']>0 for r in bad):constraint='output acceptance; inspect queue/startup attribution'
            else:constraint='no measured capacity knee'
            if o=='file_shm':constraint+='; short bounded file, not sustainable storage'
            if o=='file_disk':constraint+='; page cache/reclaim at 512 MiB, durable disk not certified'
            if o=='vxlan' and any(r['output_drop_packets'] for r in qs):constraint+='; strict LF also affected by local EPERM policy'
            lines.append(f'| {b} | {o} | {lf} | {fail} | {knee} | {peak:.6f} | {constraint} |')
    report.append('\n'.join(lines))

def costs(rs):
    lines=['## Per-packet worker CPU cost relative to null','','CPU µs/captured packet = loaded-window worker CPU fraction / whole-burst captured rate × 10⁶. This combines differing CPU and packet windows, so it is an approximate empirical average, not a cycle-exact isolated output benchmark. Output points are loss-free with a valid CPU window. Incremental cost is output minus same-backend/same-offered-target null; a null baseline with ≥99.9% captured and <90% worker CPU may be used if its tiny capture loss is explicitly labelled.','','| Backend | Offered target Mpps | Output | Total µs/captured packet | Increment over null µs/packet |','|---|---:|---|---:|---:|']
    for b in ['rv3','cv3','cv2','rrecv','rdpdk']:
        nulls={r['target']:r for r in rs if r['backend']==b and r['output']=='null' and r['captured']>=.999*r['accepted'] and r['worker_cpu_pct']<90 and r['cpu_valid'] and r['output_drop_packets']==0}
        for r in sorted([r for r in rs if r['backend']==b and r['output']!='null' and analyze.lossfree(r) and r['cpu_valid']],key=lambda r:(r['target'],r['output'])):
            n=nulls.get(r['target'])
            if n:
                cost=r['worker_cpu_pct']/100/r['captured_mpps'];base=n['worker_cpu_pct']/100/n['captured_mpps']
                label=r['output']+(f" (null capture loss {100*(1-n['captured']/n['accepted']):.4f}%)" if n['captured']<n['accepted'] else '')
                lines.append(f"| {b} | {r['target']:g} | {label} | {cost:.4f} | {cost-base:+.4f} |")
        # VXLAN's loss-free rates are far below the standard null sweep. Use the
        # median low-rate null coefficient and label this interpolation explicitly.
        vx=[r for r in rs if r['backend']==b and r['output']=='vxlan' and r['captured']==r['accepted'] and r['cpu_valid']]
        if vx and nulls:
            r=max(vx,key=lambda r:r['target']);n=min(nulls.values(),key=lambda r:r['target'])
            cost=r['worker_cpu_pct']/100/r['captured_mpps'];base=n['worker_cpu_pct']/100/n['captured_mpps']
            lines.append(f"| {b} | {r['target']:g} | VXLAN (capture loss-free; {r['output_drop_packets']} output errors; null coefficient from {n['target']:g} Mpps extrapolated) | {cost:.4f} | {cost-base:+.4f} |")
    report.append('\n'.join(lines))
    report.append('Single short bursts include CPU-frequency, scheduler and idle-poll variation; low-load C measurements vary materially, and some matched differences can be slightly negative. These are measurement differences, not negative physical output cost. Do not extrapolate a low-load coefficient to a certified capacity. VXLAN is several microseconds per captured packet; null/file/ZMQ are sub-microsecond in these ring rows. Source and the 100% CPU knee support that order of magnitude, while precise output-only CPU attribution would require repeated/profiled runs.')

def e2e(rs,checks):
    byid={q['id']:q for q in checks}
    lines=['## 3. Generator → probe → jinjiao receiver: independent accounting','','ZMQ PUSH connects to `tcp://10.0.0.10:19555`; jinjiao libzmq PULL parses the batch header and every MPLS-tagged inner record. VXLAN sends UDP to jinjiao `10.0.0.10:19556`; receiver.c uses recvmmsg and validates the inner frame, recording kernel SO_RXQ_OVFL separately. Receivers are outside worker quota. Measured warmup is excluded only after closed-count/empty-queue barrier.','','The equation tested is **generator accepted = receiver received + capture-socket drops + VF OOB + output drops + receiver socket drops**. A nonzero residual is an unresolved gap, never counted as an attributed drop.','','| Case | Generator accepted | Receiver received | Capture drops (socket + VF) | Output drops | Receiver socket drops | Unattributed residual |','|---|---:|---:|---:|---:|---:|---:|']
    for r in sorted([r for r in rs if r['output'] in ['zmq','vxlan']],key=lambda r:(r['backend'],r['output'],r['target'])):
        q=byid[r['id']]
        lines.append(f"| `{r['id']}` | {r['accepted']:,} | {r['delivered']:,} | {q['capture_drops']:,} | {r['output_drop_packets']:,} | {q['peer_drops']:,} | {q['independent_e2e_residual']:,} |")
    report.append('\n'.join(lines))
    failures=[q for q in checks if not all(q['checks'].values())]
    report.append(f"Independent validation: {len(checks)-len(failures)}/{len(checks)} selected cases pass all applicable worker-budget, capture/output/e2e accounting, packet-format and file-parser checks. Details: `continuation-validation.json`." + (f" Failed cases: {', '.join(q['id'] for q in failures)}." if failures else ''))

def comparison(rs):
    report.append('## Final aligned comparisons (supersede earlier interim tables)\n\nOne selected row per backend/output/offered target. New rechecks supersede the original ambiguous windows for conclusions; original raw records remain available. Each cell is captured / API-forwarded / independently delivered Mpps; loaded-window CPU; output drops. Null has no delivered rate. C V3 means real libpcap timeout_ms=1000; C V2 means real libpcap shipped timeout omitted/immediate mode. C is never relabelled AF_PACKET direct implementation.')
    for o in ['null','file_disk','file_shm','zmq','vxlan']:
        qs=[r for r in rs if r['output']==o and r['backend'] in ['rv3','cv3','cv2']]
        by={(r['backend'],r['target']):r for r in qs}
        lines=[f'### {o}', '', '| Offered target Mpps | Rust direct AF_PACKET V3 | Plain libpcap C V3 | Plain libpcap C default/V2 |', '|---:|---|---|---|']
        for t in sorted({r['target'] for r in qs}):
            lines.append(f'| {t:g} | '+' | '.join(report.cell(by.get((b,t))) for b in ['rv3','cv3','cv2'])+' |')
        report.append('\n'.join(lines))

if __name__=='__main__':
    rs=selected();checks=audit(rs)
    comparison(rs);summary(rs);costs(rs);e2e(rs,checks)
    (P/'selected-summary.json').write_text(json.dumps([{k:r[k] for k in ['id','backend','output','target','offered_mpps','captured_mpps','delivered_mpps','worker_cpu_pct','delta','accepted','captured','forwarded','delivered','memory_max','cpu_window_seconds']} for r in rs],indent=2))
    print(json.dumps({'selected':len(rs),'validation_failures':[q['id'] for q in checks if not all(q['checks'].values())]}))
