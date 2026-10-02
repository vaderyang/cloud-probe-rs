#!/usr/bin/env python3
"""Run the OneBoot lab verification for every target in an inventory.

Thin driver over ``lab_verify.py``: it resolves each target's artifact from a
dist directory, expands the environment-variable secrets named in the
inventory (``bmc.pass_env`` / ``ssh.key_env``), runs one verification per
target and aggregates the exit status.

    tools/oneboot/run_inventory.py \
        --inventory tools/oneboot/inventory.json \
        --artifact-dir dist --apply --junit-dir build/lab-junit

Adding a platform is a data change (a new entry in the inventory), not a code
change.  See ``docs/ONEBOOT_LAB.md``.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
LAB_VERIFY = HERE / "lab_verify.py"
VM_VERIFY = HERE / "vm_verify.py"


def _resolve_secret(spec: dict[str, Any], value_key: str, env_key: str,
                    *, allow_missing: bool = False) -> str | None:
    """Return an inline value or the content of the named environment variable."""
    if spec.get(value_key):
        return str(spec[value_key])
    env_name = spec.get(env_key)
    if env_name:
        val = os.environ.get(env_name)
        if not val:
            if allow_missing:
                return f"<unset:{env_name}>"
            raise SystemExit(
                f"secret env {env_name!r} referenced by the inventory is not set"
            )
        return val
    return None


def _find_artifact(artifact_dir: pathlib.Path, target: str) -> pathlib.Path:
    # Inventories kept outside the tree (the LAB_INVENTORY_JSON secret, a local
    # inventory.json) still name the Linux targets with the `-glibc217` suffix,
    # which release.yml dropped when the glibc 2.17 container build became the
    # default `*-unknown-linux-gnu` recipe.  Accepting the old spelling keeps a
    # stale inventory pointing at the tarball that is actually published.
    target = target.removesuffix("-glibc217")
    # Exact name first: a leftover `-glibc217` tarball in the same dist directory
    # sorts *before* the plain one (b'-' < b'.'), so a bare glob could pick the
    # stale artifact.
    exact = artifact_dir / f"cloud-probe-rs-{target}.tar.gz"
    if exact.is_file():
        return exact
    matches = sorted(artifact_dir.glob(f"cloud-probe-rs-{target}*.tar.gz"))
    if not matches:
        raise SystemExit(f"no cloud-probe-rs-{target}*.tar.gz under {artifact_dir}")
    return matches[0]


def build_argv(entry: dict[str, Any], args: argparse.Namespace,
               artifact: pathlib.Path, junit_dir: pathlib.Path,
               ssh_key_file: str | None) -> list[str]:
    argv = [
        sys.executable, str(LAB_VERIFY),
        "verify-ssh" if args.verify_ssh else "run",
        "--artifact", str(artifact),
        "--target-name", entry["name"],
        "--boot-style", entry.get("boot_style", "redhat"),
        "--junit-out", str(junit_dir / f"{entry['name']}.junit.xml"),
        "--result-out", str(junit_dir / f"{entry['name']}.result.json"),
    ]
    if entry.get("source"):
        argv += ["--source", entry["source"]]
    if entry.get("mac"):
        argv += ["--mac", entry["mac"]]
    if args.oneboot:
        argv += ["--oneboot", args.oneboot]
    if args.apply:
        argv.append("--apply")
    if args.trigger:
        argv += ["--trigger", args.trigger]

    bmc = entry.get("bmc") or {}
    if bmc.get("host"):
        argv += ["--bmc-host", str(bmc["host"])]
        argv += ["--bmc-interface", str(bmc.get("interface", "lanplus"))]
        if bmc.get("user"):
            argv += ["--bmc-user", str(bmc["user"])]
        pw = _resolve_secret(bmc, "pass", "pass_env", allow_missing=args.dry_run)
        if pw:
            argv += ["--bmc-pass", pw]
        if bmc.get("efi"):
            argv.append("--efi")

    ssh = entry.get("ssh") or {}
    if ssh.get("host"):
        argv += ["--ssh-host", str(ssh["host"])]
        argv += ["--ssh-port", str(ssh.get("port", 22))]
        if ssh.get("user"):
            argv += ["--ssh-user", str(ssh["user"])]
        if ssh_key_file:
            argv += ["--ssh-key", ssh_key_file]
    return argv


def build_vm_argv(entry: dict[str, Any], args: argparse.Namespace,
                  artifact: pathlib.Path, junit_dir: pathlib.Path) -> list[str]:
    """QEMU/KVM driver: install the source in a local VM and verify there.

    Resources can be overridden per target via the inventory's ``vm`` block
    (``cpus``, ``mem``, ``disk``, ``iso``, ``dist_host``).
    """
    vm = entry.get("vm") or {}
    workdir = pathlib.Path(args.vm_workdir) / entry["name"]
    argv = [
        sys.executable, str(VM_VERIFY),
        "--artifact", str(artifact),
        "--source", entry["source"],
        "--target-name", entry["name"],
        "--boot-style", entry.get("boot_style", "redhat"),
        "--junit-out", str(junit_dir / f"{entry['name']}.junit.xml"),
        "--result-out", str(junit_dir / f"{entry['name']}.result.json"),
        "--workdir", str(workdir),
        "--vm-cpus", str(vm.get("cpus", args.vm_cpus)),
        "--vm-mem", str(vm.get("mem", args.vm_mem)),
        "--vm-disk-size", str(vm.get("disk", args.vm_disk_size)),
    ]
    if args.oneboot:
        argv += ["--oneboot", args.oneboot]
    iso = entry.get("iso") or vm.get("iso")
    if iso:
        argv += ["--iso", str(iso)]
    dist_host = entry.get("dist_host") or vm.get("dist_host")
    if dist_host:
        argv += ["--dist-host", str(dist_host)]
    if entry.get("frames"):
        argv += ["--frames", str(entry["frames"])]
    return argv


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--inventory", default=str(HERE / "inventory.json"))
    p.add_argument("--artifact-dir", default="dist")
    p.add_argument("--junit-dir", default="build/lab-junit")
    p.add_argument("--oneboot", help="override the inventory's OneBoot URL")
    p.add_argument("--target", action="append", default=[],
                   help="verify only this target name (repeatable)")
    p.add_argument("--driver", choices=["oneboot", "vm"], default="oneboot",
                   help="oneboot = PXE/BMC lab machines; vm = local QEMU/KVM")
    p.add_argument("--vm-workdir",
                   default=str(pathlib.Path(tempfile.gettempdir()) / "cprs-vm"),
                   help="per-target VM workdir (also caches the ISO)")
    p.add_argument("--vm-cpus", type=int, default=4)
    p.add_argument("--vm-mem", type=int, default=6144)
    p.add_argument("--vm-disk-size", default="20G")
    p.add_argument("--apply", action="store_true",
                   help="actually provision; without it every run is a dry run")
    p.add_argument("--trigger", choices=["manual", "ipmi", "none"])
    p.add_argument("--verify-ssh", action="store_true",
                   help="skip PXE and run the smoke on already-installed hosts")
    p.add_argument("--dry-run", action="store_true",
                   help="print the commands without executing them")
    args = p.parse_args(argv)

    inv_path = pathlib.Path(args.inventory)
    if not inv_path.is_file():
        raise SystemExit(
            f"inventory {inv_path} not found; copy inventory.example.json and edit it"
        )
    inv = json.loads(inv_path.read_text())
    targets = [t for t in inv.get("targets", [])
               if not args.target or t["name"] in args.target]
    if not targets:
        raise SystemExit("no matching targets")

    artifact_dir = pathlib.Path(args.artifact_dir)
    junit_dir = pathlib.Path(args.junit_dir)
    junit_dir.mkdir(parents=True, exist_ok=True)
    if args.oneboot is None and inv.get("oneboot"):
        args.oneboot = inv["oneboot"]

    # Materialise an SSH key from the environment once for every target that
    # names one, then remove it when the run finishes.  (VM runs need no SSH.)
    key_path: str | None = None
    ssh_key_file: str | None = None
    if args.driver == "oneboot":
        for t in targets:
            ssh = t.get("ssh") or {}
            if ssh.get("key"):
                ssh_key_file = str(ssh["key"])
                break
            if ssh.get("key_env"):
                content = _resolve_secret({"key_env": ssh["key_env"]}, "key", "key_env",
                                          allow_missing=args.dry_run)
                if content and not content.startswith("<unset:"):
                    fd, key_path = tempfile.mkstemp(prefix="cprs-sshkey-")
                    os.close(fd)
                    pathlib.Path(key_path).write_text(content)
                    os.chmod(key_path, 0o600)
                    ssh_key_file = key_path
                break

    failures = 0
    try:
        for entry in targets:
            if not entry.get("source") and not args.verify_ssh:
                print(f"skip {entry['name']}: no 'source' in the inventory")
                failures += 1
                continue
            artifact = _find_artifact(artifact_dir, entry["artifact"])
            if args.driver == "vm":
                entry_argv = build_vm_argv(entry, args, artifact, junit_dir)
            else:
                entry_argv = build_argv(entry, args, artifact, junit_dir, ssh_key_file)
            print(f"\n===== {entry['name']} =====")
            print("  " + " ".join(_redact(entry_argv)))
            if args.dry_run:
                continue
            rc = subprocess.run(entry_argv, check=False).returncode
            if rc != 0:
                failures += 1
    finally:
        if key_path:
            pathlib.Path(key_path).unlink(missing_ok=True)

    print(f"\nlab verification: {len(targets) - failures}/{len(targets)} target(s) passed")
    return 1 if failures else 0


def _redact(argv: list[str]) -> list[str]:
    out = list(argv)
    for i, tok in enumerate(out):
        if tok == "--bmc-pass" and i + 1 < len(out):
            out[i + 1] = "***"
    return out


if __name__ == "__main__":
    raise SystemExit(main())
