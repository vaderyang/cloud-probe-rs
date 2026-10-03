#!/usr/bin/env python3
"""Run an already-built release unit-test executable in worker-only cgroups."""
import argparse
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('binary', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--repeat', type=int, default=3)
parser.add_argument('--ablation', action='store_true')
args = parser.parse_args()
binary = str(args.binary.resolve())
base = ['sudo', '-n', 'systemd-run', '--scope', '-q', '-p', 'CPUQuota=100%',
        '-p', 'MemoryMax=512M', 'setpriv', '--reuid=1000', '--regid=1000',
        '--init-groups', 'taskset', '-c', '24,25', 'env']
with args.output.open('w') as output:
    cases = [('rtc', 0, 'ring'), ('pipeline', 0, 'ring'),
             ('rtc', 0, 'eof'), ('pipeline', 0, 'eof')]
    cases += [(model, rate, '') for rate in (100000, 300000, 800000)
              for model in ('rtc', 'pipeline')]
    if args.ablation:
        cases = [('pipeline', rate, '') for rate in (100000, 300000, 800000)]
    for repeat in range(args.repeat):
        for model, rate, idle in cases:
            variants = [('poll', 'off'), ('park', 'off'), ('poll', 'on'), ('park', 'on')] if args.ablation else [('park', 'on')]
            for wait, recycle in variants:
                env = dict(os.environ, PROBE_MODEL=model, PROBE_PPS=str(rate),
                           PROBE_IDLE=idle, PROBE_WAIT=wait, PROBE_RECYCLE=recycle)
                result = subprocess.run(base + [f'{key}={env[key]}' for key in ('PROBE_MODEL', 'PROBE_PPS', 'PROBE_IDLE', 'PROBE_WAIT', 'PROBE_RECYCLE')] + [binary, '--exact', 'task::tests::pipeline_cost_probe',
                                                '--ignored', '--nocapture'],
                                        env=env, capture_output=True, text=True, timeout=60)
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
                row = json.loads(next(line.split('PROBE ', 1)[1] for line in result.stdout.splitlines()
                                      if 'PROBE ' in line))
                row.update(repeat=repeat, wait=wait, recycle=recycle)
                output.write(json.dumps(row, sort_keys=True) + '\n')
                output.flush()
                print({key: row[key] for key in ('model', 'pps', 'idle', 'wait', 'recycle', 'cores')}, flush=True)
    if not args.ablation:
        result = subprocess.run(base + [binary, '--exact', 'task::tests::pipeline_latency_probe',
                                        '--ignored', '--nocapture'],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        args.output.with_suffix('.latency.log').write_text(result.stdout + result.stderr)
        print(result.stdout, flush=True)
