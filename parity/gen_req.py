#!/usr/bin/env python3
"""Generate req_pattern match queries for the C/Rust differential test."""
import random
import sys

random.seed(int(sys.argv[2]) if len(sys.argv) > 2 else 7)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000


def ipv4():
    return ".".join(str(random.randrange(256)) for _ in range(4))


def ipv6():
    return ":".join(f"{random.randrange(65536):x}" for _ in range(8))


def port():
    return random.choice([0, 1, 22, 80, 443, 8011, 8012, 4789, 65535, random.randrange(65536)])


def host():
    return random.choice([ipv4(), ipv4(), ipv4(), ipv6()])


def condition():
    # literal hosts only (nic.* depends on the host environment)
    if random.random() < 0.6:
        return f"host {host()}"
    return f"port {port()}"


def expr(depth=0):
    r = random.random()
    if depth < 2 and r < 0.4:
        return f"({term(depth + 1)} {random.choice(['and', 'or'])} {term(depth + 1)})"
    return term(depth)


def term(depth):
    return expr(depth) if depth < 2 and random.random() < 0.35 else condition()


def query():
    return host(), port()


for _ in range(N):
    pat = expr()
    # invalid patterns sometimes
    if random.random() < 0.1:
        pat = random.choice(
            [
                "host",
                "port",
                "host x.y.z.w",
                "port 99999",
                "host 1.2.3.4 and",
                "(host 1.2.3.4",
                "host 1.2.3.4 port 80",
                "",
            ]
        )
    ip, p = query()
    print(f"{pat}\t{ip}\t{p}")
