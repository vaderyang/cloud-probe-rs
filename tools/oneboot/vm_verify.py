#!/usr/bin/env python3
"""Run the OneBoot on-target verification inside a local QEMU/KVM VM.

Physical lab machines need BMC/IPMI and a PXE-capable L2 segment.  When neither
is available, this boots the *same* installer + kickstart/autoinstall in a VM
instead: it fetches the installer kernel/initrd and the ISO from OneBoot,
serves the installer source and the payload locally, boots QEMU, and collects
the same result.json the physical path produces.

Two things make this work where a naive PXE-in-a-VM does not:

  * OneBoot's stage2 **session** is cleaned up mid-install when it cannot see
    the client's DHCP lease (a VM behind slirp never appears as a client), so
    the ISO is served from this host instead of the session.
  * QEMU user-mode networking maps the host to 10.0.2.2, so the kickstart's
    payload URL (and the callback) point there.

Boot styles (mirroring OneBoot's `boot_style`):

  redhat   anaconda: serves the mounted ISO tree and boots
           ``inst.repo=<tree> inst.ks=<kickstart>``.
  casper   Ubuntu live-server Autoinstall: serves the raw ISO and boots
           ``url=<iso> autoinstall ds=nocloud-net;s=<user-data dir>``, where the
           dir holds user-data/meta-data built from the rendered autoinstall.

Requirements: qemu-system-x86_64, qemu-img, KVM access, sudo (loop-mount; not
needed for casper), and either nginx or python3 for the source server.  The ISO
is cached under --workdir so repeat runs skip the download.

    tools/oneboot/vm_verify.py \
        --artifact dist/cloud-probe-rs-x86_64-unknown-linux-gnu-glibc217.tar.gz \
        --source centos_7_9_x86_64_dvd_2009 --boot-style redhat \
        --junit-out build/vm-junit/centos7.xml

    tools/oneboot/vm_verify.py \
        --artifact dist/cloud-probe-rs-x86_64-unknown-linux-gnu-glibc217.tar.gz \
        --source ubuntu_24_04_3_live_server_amd64 --boot-style casper \
        --vm-disk-size 30G --junit-out build/vm-junit/ubuntu2404.xml
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from lab_verify import (
    StageServer,
    _sha256,
    print_summary,
    render_kickstart,
    write_junit,
)

# QEMU user-mode networking maps the gateway/host to this address.
QEMU_HOST = "10.0.2.2"


def _run(cmd: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=False, text=True, **kw)  # type: ignore[arg-type]


def _fetch(url: str, dest: pathlib.Path) -> None:
    if dest.exists() and dest.stat().st_size > 0:
        print(f"[iso] cached {dest}")
        return
    if not url.startswith(("http://", "https://")):
        raise SystemExit(f"refusing non-http(s) URL: {url}")
    print(f"[fetch] {url}\n     -> {dest}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    if shutil.which("curl"):
        cmd = ["curl", "-fsSL", "--retry", "5", "--retry-connrefused", "-o", str(tmp), url]
    elif shutil.which("wget"):
        cmd = ["wget", "-q", "-O", str(tmp), url]
    else:
        raise SystemExit("neither curl nor wget is available to fetch the installer image")
    _run(cmd).check_returncode()
    tmp.rename(dest)


def _mount_iso(iso: pathlib.Path, mnt: pathlib.Path) -> None:
    mnt.mkdir(parents=True, exist_ok=True)
    if _run(["mountpoint", "-q", str(mnt)]).returncode == 0:
        return
    _run(["sudo", "mount", "-o", "loop,ro", str(iso), str(mnt)]).check_returncode()


def _unmount_iso(mnt: pathlib.Path) -> None:
    _run(["sudo", "umount", str(mnt)])


def _start_repo(root: pathlib.Path, port: int, workdir: pathlib.Path) -> subprocess.Popen[str] | None:
    """Serve ``root``.  Prefer nginx (anaconda stalls against python's
    http.server over slirp); fall back to python if nginx is absent."""
    if shutil.which("nginx"):
        conf = workdir / "nginx.conf"
        conf.write_text(
            "events {}\n"
            "http {\n"
            "  include /etc/nginx/mime.types;\n"
            f"  server {{ listen {port}; root {root}; autoindex on; "
            "sendfile off; }\n"
            "}\n"
        )
        proc = subprocess.Popen(
            ["sudo", "nginx", "-c", str(conf), "-g", f"pid {workdir}/nginx.pid;"],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, text=True,
        )
        time.sleep(1)
        return proc
    # No --bind: http.server defaults to all interfaces, which the guest needs.
    return subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--directory", str(root)],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, text=True,
    )


def _stop_repo(proc: subprocess.Popen[str] | None, port: int, workdir: pathlib.Path) -> None:
    if shutil.which("nginx") and (workdir / "nginx.pid").exists():
        _run(["sudo", "nginx", "-c", str(workdir / "nginx.conf"),
              "-g", f"pid {workdir}/nginx.pid;", "-s", "stop"])
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _stage_nocloud(stage: pathlib.Path, user_data: str) -> str:
    """Write a NoCloud datasource dir and return its base URL path."""
    nocloud = stage / "nocloud"
    nocloud.mkdir(parents=True, exist_ok=True)
    (nocloud / "user-data").write_text(user_data)
    (nocloud / "meta-data").write_text("instance-id: cprs-vm\nlocal-hostname: cprs\n")
    return "/nocloud/"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifact", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--boot-style", default="redhat", choices=["redhat", "casper"])
    p.add_argument("--oneboot", default="https://oneboot.netisdev.com")
    p.add_argument("--dist-host", default="10.40.1.254",
                   help="OneBoot HTTP distribution host (images + /iso)")
    p.add_argument("--iso", help="local ISO path (default: derive + download)")
    p.add_argument("--target-name", default="vm")
    p.add_argument("--frames", type=int, default=2000)
    p.add_argument("--serve-port", type=int, default=8000)
    p.add_argument("--repo-port", type=int, default=8001)
    p.add_argument("--vm-cpus", type=int, default=4)
    p.add_argument("--vm-mem", type=int, default=6144)
    p.add_argument("--vm-disk-size", default="20G")
    p.add_argument("--timeout", type=float, default=2400.0)
    p.add_argument("--workdir", default=str(pathlib.Path(tempfile.gettempdir()) / "cprs-vm"))
    p.add_argument("--junit-out")
    p.add_argument("--result-out")
    p.add_argument("--keep", action="store_true", help="keep the VM disk after the run")
    args = p.parse_args(argv)

    workdir = pathlib.Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    stage = workdir / "stage"
    stage.mkdir(parents=True, exist_ok=True)
    artifact = pathlib.Path(args.artifact).resolve()
    if not artifact.is_file():
        raise SystemExit(f"artifact not found: {artifact}")
    shutil.copyfile(artifact, stage / artifact.name)
    shutil.copyfile(pathlib.Path(__file__).resolve().parent / "on_target_smoke.sh",
                    stage / "on_target_smoke.sh")
    sha256 = _sha256(stage / artifact.name)

    redhat = args.boot_style == "redhat"
    base = f"http://{QEMU_HOST}:{args.serve_port}"

    # 1. Render the answer file (kickstart for anaconda, autoinstall for casper)
    #    with the payload + callback pointed at the QEMU host alias.
    answer = render_kickstart(
        args.boot_style, base=base, archive=artifact.name, sha256=sha256,
        callback=f"{base}/result", frames=args.frames)

    # 2. Installer kernel/initrd + the ISO (cached).  OneBoot extracts
    #    /images/<source>/ lazily on a /go request and cleans it with the
    #    session, so trigger one first (we do not use its session or stage2).
    mac = "52:54:00:1b:00:01"
    go = (f"http://{args.dist_host}:8088/boot/{args.source}/go"
          f"?mac={mac.replace(':', '-')}&ks=cprs-verify.cfg")
    _run(["curl", "-fsS", "-o", "/dev/null", go])
    img = f"http://{args.dist_host}:8080/images/{args.source}"
    _fetch(f"{img}/vmlinuz", workdir / "vmlinuz")
    _fetch(f"{img}/initrd", workdir / "initrd")

    if args.iso:
        iso = pathlib.Path(args.iso).resolve()
    else:
        iso = workdir / "os.iso"
        rel = args.source
        try:
            import oneboot_client
            src = oneboot_client.OneBoot(args.oneboot).find_source(args.source)
            if src and src.get("rel_path"):
                rel = src["rel_path"]
        except Exception as exc:  # noqa: BLE001 - best effort, path may still work
            print(f"[warn] could not resolve rel_path: {exc}", file=sys.stderr)
        _fetch(f"http://{args.dist_host}:8080/iso/{rel}", iso)

    # 3. Expose the installer source and build the kernel command line.
    mnt = workdir / "mnt"
    if redhat:
        (stage / "cprs-verify.cfg").write_text(answer)
        _mount_iso(iso, mnt)
        repo_root = mnt
        boot = (
            f"inst.repo=http://{QEMU_HOST}:{args.repo_port}/ "
            f"inst.stage2=http://{QEMU_HOST}:{args.repo_port}/ "
            f"inst.ks=http://{QEMU_HOST}:{args.serve_port}/cprs-verify.cfg"
        )
    else:
        # casper boots the ISO by URL and pulls the autoinstall from a NoCloud
        # net datasource.
        nocloud = _stage_nocloud(stage, answer)
        # casper fetches the raw ISO by name, so serve the directory that holds
        # it (it may be outside --workdir when --iso is given).
        repo_root = iso.parent
        boot = (
            "boot=casper netboot=url "
            f"url=http://{QEMU_HOST}:{args.repo_port}/{iso.name} "
            f"autoinstall ds=nocloud-net;s=http://{QEMU_HOST}:{args.serve_port}{nocloud} "
            "root=/dev/ram0 ramdisk_size=5242880"
        )

    repo = _start_repo(repo_root, args.repo_port, workdir)
    append = (f"{boot} ip=dhcp rd.neednet=1 ipv6.disable=1 "
              "inst.text console=ttyS0,115200 ---")

    disk = workdir / "disk.qcow2"
    disk.unlink(missing_ok=True)
    _run(["qemu-img", "create", "-q", "-f", "qcow2", str(disk), args.vm_disk_size]).check_returncode()

    qemu_cmd = [
        "qemu-system-x86_64", "-enable-kvm", "-cpu", "host",
        "-smp", str(args.vm_cpus), "-m", str(args.vm_mem),
        "-name", f"cprs-{args.target_name}",
        "-kernel", str(workdir / "vmlinuz"), "-initrd", str(workdir / "initrd"),
        "-append", append,
        "-drive", f"file={disk},if=virtio,format=qcow2",
        "-netdev", "user,id=n0",
        "-device", f"virtio-net-pci,netdev=n0,mac={mac}",
        "-nographic", "-no-reboot",
    ]
    log = (workdir / "qemu.log").open("w")
    print(f"[vm] booting {args.source} ({args.target_name}, {args.boot_style})")
    qemu = subprocess.Popen(qemu_cmd, stdout=log, stderr=subprocess.STDOUT, text=True)

    result: dict[str, object] | None = None
    error: str | None = None
    try:
        with StageServer(stage, "", args.serve_port) as server:
            print(f"[stage] {base} serving {stage}")
            result = server.wait_result(timeout=args.timeout)
            if result is None:
                error = f"no result within {args.timeout}s (qemu log: {workdir/'qemu.log'})"
    finally:
        qemu.terminate()
        try:
            qemu.wait(timeout=10)
        except subprocess.TimeoutExpired:
            qemu.kill()
        log.close()
        _stop_repo(repo, args.repo_port, workdir)
        if redhat:
            _unmount_iso(mnt)
        if not args.keep:
            disk.unlink(missing_ok=True)

    if args.result_out and result is not None:
        pathlib.Path(args.result_out).write_text(json.dumps(result, indent=2))
    if args.junit_out:
        write_junit(pathlib.Path(args.junit_out), args.target_name, result, error)
    return print_summary(args.target_name, result, error)


if __name__ == "__main__":
    raise SystemExit(main())
